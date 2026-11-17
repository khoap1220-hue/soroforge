package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/soroworks/soroforge/internal/config"
	"github.com/soroworks/soroforge/internal/store"
)

const (
	// DefaultWebhookTimeout bounds a single webhook delivery attempt.
	DefaultWebhookTimeout = 10 * time.Second

	// DefaultWebhookMaxAttempts bounds total delivery attempts (1 initial + 3 retries).
	DefaultWebhookMaxAttempts = 4

	// DefaultWebhookBaseBackoff is the initial retry delay before exponential growth.
	DefaultWebhookBaseBackoff = 200 * time.Millisecond

	// DefaultWebhookMaxBackoff caps both computed backoff and Retry-After delays.
	DefaultWebhookMaxBackoff = 5 * time.Second

	// DefaultWebhookTotalTimeout bounds the entire delivery cycle across retries
	// so an unresponsive receiver cannot stall a deploy or upgrade result.
	DefaultWebhookTotalTimeout = 30 * time.Second
)

// WebhookStatus reports the outcome of delivering a webhook to one URL.
type WebhookStatus struct {
	URL      string `json:"url"`
	OK       bool   `json:"ok"`
	Attempts int    `json:"attempts,omitempty"`
	Error    string `json:"error,omitempty"`
}

// WebhookPayload is the JSON payload sent to configured webhook endpoints after
// a confirmed deploy or upgrade.
type WebhookPayload struct {
	Alias          string       `json:"alias"`
	Network        string       `json:"network"`
	ContractID     string       `json:"contract_id"`
	Contract       string       `json:"contract,omitempty"`
	WasmHash       string       `json:"wasm_hash"`
	Action         store.Action `json:"action"`
	DeployerPubkey string       `json:"deployer_pubkey"`
	TxHash         string       `json:"tx_hash,omitempty"`
	Tx             string       `json:"tx,omitempty"`
	Ledger         uint32       `json:"ledger,omitempty"`
	Notes          string       `json:"notes,omitempty"`
}

// WebhookSender delivers webhooks.
type WebhookSender interface {
	Send(ctx context.Context, webhook config.Webhook, payload WebhookPayload) error
}

// webhookDeliverer is an optional extension implemented by senders that report
// how many delivery attempts were made.
type webhookDeliverer interface {
	Deliver(ctx context.Context, webhook config.Webhook, payload WebhookPayload) (int, error)
}

// WebhookRetryOptions configures bounded retry and backoff behaviour for HTTPWebhookSender.
// Zero or nil fields select production defaults.
type WebhookRetryOptions struct {
	MaxAttempts  int
	BaseBackoff  time.Duration
	MaxBackoff   time.Duration
	TotalTimeout time.Duration

	// Sleep pauses between attempts. Tests replace it to assert on schedules
	// without sleeping.
	Sleep func(ctx context.Context, d time.Duration) error

	// Now returns the current time when parsing HTTP-date Retry-After headers.
	Now func() time.Time

	// Jitter randomises a computed backoff duration. Nil uses [0.5*d, 1.5*d).
	Jitter func(d time.Duration) time.Duration
}

// HTTPWebhookSender delivers webhooks via HTTP POST with bounded retries.
type HTTPWebhookSender struct {
	client       *http.Client
	maxAttempts  int
	baseBackoff  time.Duration
	maxBackoff   time.Duration
	totalTimeout time.Duration
	sleep        func(ctx context.Context, d time.Duration) error
	now          func() time.Time
	jitter       func(d time.Duration) time.Duration
}

var (
	_ WebhookSender    = (*HTTPWebhookSender)(nil)
	_ webhookDeliverer = (*HTTPWebhookSender)(nil)
)

// NewHTTPWebhookSender returns a WebhookSender using client, or an http.Client with
// DefaultWebhookTimeout when client is nil.
func NewHTTPWebhookSender(client *http.Client) *HTTPWebhookSender {
	return NewHTTPWebhookSenderWithOptions(client, WebhookRetryOptions{})
}

// NewHTTPWebhookSenderWithOptions returns an HTTPWebhookSender with custom retry settings.
func NewHTTPWebhookSenderWithOptions(client *http.Client, opts WebhookRetryOptions) *HTTPWebhookSender {
	if client == nil {
		client = &http.Client{Timeout: DefaultWebhookTimeout}
	}
	maxAttempts := opts.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultWebhookMaxAttempts
	}
	baseBackoff := opts.BaseBackoff
	if baseBackoff <= 0 {
		baseBackoff = DefaultWebhookBaseBackoff
	}
	maxBackoff := opts.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = DefaultWebhookMaxBackoff
	}
	totalTimeout := opts.TotalTimeout
	if totalTimeout <= 0 {
		totalTimeout = DefaultWebhookTotalTimeout
	}
	sleepFn := opts.Sleep
	if sleepFn == nil {
		sleepFn = waitForRetry
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	jitterFn := opts.Jitter
	if jitterFn == nil {
		jitterFn = defaultWebhookJitter
	}
	return &HTTPWebhookSender{
		client:       client,
		maxAttempts:  maxAttempts,
		baseBackoff:  baseBackoff,
		maxBackoff:   maxBackoff,
		totalTimeout: totalTimeout,
		sleep:        sleepFn,
		now:          nowFn,
		jitter:       jitterFn,
	}
}

func defaultWebhookJitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + time.Duration(rand.Int63n(int64(d)))
}

// Send delivers a JSON payload to a webhook URL, retrying transient failures.
func (s *HTTPWebhookSender) Send(ctx context.Context, wh config.Webhook, payload WebhookPayload) error {
	_, err := s.Deliver(ctx, wh, payload)
	return err
}

// Deliver sends payload to wh.URL and returns the number of HTTP attempts made.
func (s *HTTPWebhookSender) Deliver(ctx context.Context, wh config.Webhook, payload WebhookPayload) (int, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal webhook payload: %w", err)
	}

	var signature string
	if wh.Secret != "" {
		mac := hmac.New(sha256.New, []byte(wh.Secret))
		mac.Write(raw)
		signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	deliveryCtx, cancel := context.WithTimeout(ctx, s.totalTimeout)
	defer cancel()

	var lastErr error
	for attempt := 1; attempt <= s.maxAttempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(deliveryCtx, http.MethodPost, wh.URL, bytes.NewReader(raw))
		if reqErr != nil {
			return attempt - 1, fmt.Errorf("create webhook request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "SoroForge-Webhook")
		if signature != "" {
			req.Header.Set("X-SoroForge-Signature", signature)
		}

		resp, doErr := s.client.Do(req)
		var retryAfterHeader string
		var statusCode int
		if resp != nil {
			statusCode = resp.StatusCode
			retryAfterHeader = resp.Header.Get("Retry-After")
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
		}

		if doErr == nil && statusCode >= 200 && statusCode < 300 {
			return attempt, nil
		}

		if doErr != nil {
			lastErr = fmt.Errorf("deliver webhook: %w", doErr)
		} else {
			lastErr = fmt.Errorf("webhook returned status %s", resp.Status)
			if !isRetryableWebhookStatus(statusCode) {
				return attempt, lastErr
			}
		}

		if attempt == s.maxAttempts || deliveryCtx.Err() != nil {
			return attempt, lastErr
		}

		delay := s.nextDelay(attempt, statusCode, retryAfterHeader)
		if err := s.sleep(deliveryCtx, delay); err != nil {
			return attempt, lastErr
		}
	}

	return s.maxAttempts, lastErr
}

func isRetryableWebhookStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

func (s *HTTPWebhookSender) nextDelay(attempt, statusCode int, retryAfter string) time.Duration {
	if (statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable) && retryAfter != "" {
		if parsed, ok := parseRetryAfter(retryAfter, s.now()); ok {
			if parsed > s.maxBackoff {
				return s.maxBackoff
			}
			return parsed
		}
	}

	delay := s.baseBackoff
	for i := 1; i < attempt && delay < s.maxBackoff; i++ {
		delay *= 2
		if delay > s.maxBackoff {
			delay = s.maxBackoff
		}
	}
	delay = s.jitter(delay)
	if delay < 0 {
		return 0
	}
	if delay > s.maxBackoff {
		return s.maxBackoff
	}
	return delay
}

func parseRetryAfter(raw string, now time.Time) (time.Duration, bool) {
	val := strings.TrimSpace(raw)
	if val == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(val); err == nil {
		if secs <= 0 {
			return 0, true
		}
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(val); err == nil {
		d := at.Sub(now)
		if d <= 0 {
			return 0, true
		}
		return d, true
	}
	return 0, false
}
