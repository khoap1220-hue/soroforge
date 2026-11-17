package deploy_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soroworks/soroforge/internal/config"
	"github.com/soroworks/soroforge/internal/deploy"
	"github.com/soroworks/soroforge/internal/stellar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeployNotifiesWebhookWithSignature(t *testing.T) {
	var (
		mu       sync.Mutex
		received []deploy.WebhookPayload
		rawBody  []byte
		gotSig   string
	)

	secret := "my-shared-secret-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		gotSig = r.Header.Get("X-SoroForge-Signature")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rawBody = body

		var payload deploy.WebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received = append(received, payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := fmt.Sprintf(`
version: 1
default_network: testnet
networks:
  testnet:
    rpc_url: https://rpc.example.org
    passphrase: "Test SDF Network ; September 2015"
    webhooks:
      - url: %s
        secret: %s
contracts:
  counter:
    wasm: ./counter.wasm
`, srv.URL, secret)

	h := newHarness(t, harnessOptions{configBody: cfg})

	result, err := h.svc.Deploy(context.Background(), deploy.DeployRequest{
		Alias: "counter",
		Notes: "initial release",
	})
	require.NoError(t, err)

	require.Len(t, result.Webhooks, 1)
	assert.True(t, result.Webhooks[0].OK)
	assert.Equal(t, srv.URL, result.Webhooks[0].URL)

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, received, 1)
	p := received[0]
	assert.Equal(t, "counter", p.Alias)
	assert.Equal(t, "testnet", p.Network)
	assert.Equal(t, h.contractID, p.ContractID)
	assert.Equal(t, "deploy", string(p.Action))
	assert.Equal(t, "initial release", p.Notes)

	// Verify HMAC-SHA256 signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(rawBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expectedSig, gotSig)
}

func TestUpgradeNotifiesWebhook(t *testing.T) {
	var (
		mu       sync.Mutex
		received []deploy.WebhookPayload
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		var payload deploy.WebhookPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		received = append(received, payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := fmt.Sprintf(`
version: 1
default_network: testnet
networks:
  testnet:
    rpc_url: https://rpc.example.org
    passphrase: "Test SDF Network ; September 2015"
    webhooks:
      - %s
contracts:
  counter:
    wasm: ./counter.wasm
`, srv.URL)

	h := newHarness(t, harnessOptions{configBody: cfg, wasm: upgradedWasm})
	trackContract(t, h, stellar.WasmHash([]byte(testWasm)))

	result, err := h.svc.Upgrade(context.Background(), deploy.UpgradeRequest{
		Alias: "counter",
		Notes: "security patch",
	})
	require.NoError(t, err)

	require.Len(t, result.Webhooks, 1)
	assert.True(t, result.Webhooks[0].OK)

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, received, 1)
	assert.Equal(t, "counter", received[0].Alias)
	assert.Equal(t, "testnet", received[0].Network)
	assert.Equal(t, "upgrade", string(received[0].Action))
	assert.Equal(t, "security patch", received[0].Notes)
}

func TestDeployWebhookFailureDoesNotFailTheDeploy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal service unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()

	cfg := fmt.Sprintf(`
version: 1
default_network: testnet
networks:
  testnet:
    rpc_url: https://rpc.example.org
    passphrase: "Test SDF Network ; September 2015"
    webhooks:
      - %s
contracts:
  counter:
    wasm: ./counter.wasm
`, srv.URL)

	h := newHarness(t, harnessOptions{configBody: cfg})

	result, err := h.svc.Deploy(context.Background(), deploy.DeployRequest{Alias: "counter"})
	require.NoError(t, err, "a failing webhook must not fail the deploy")

	require.Len(t, result.Webhooks, 1)
	assert.False(t, result.Webhooks[0].OK)
	assert.Contains(t, result.Webhooks[0].Error, "502")

	// Deploy is still tracked in the store
	tracked, err := h.store.GetContract(context.Background(), "testnet", "counter")
	require.NoError(t, err)
	assert.Equal(t, h.contractID, tracked.ContractID)
}

func TestDeployDryRunDoesNotNotifyWebhook(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := fmt.Sprintf(`
version: 1
default_network: testnet
networks:
  testnet:
    rpc_url: https://rpc.example.org
    passphrase: "Test SDF Network ; September 2015"
    webhooks:
      - %s
contracts:
  counter:
    wasm: ./counter.wasm
`, srv.URL)

	h := newHarness(t, harnessOptions{configBody: cfg})

	result, err := h.svc.Deploy(context.Background(), deploy.DeployRequest{
		Alias:  "counter",
		DryRun: true,
	})
	require.NoError(t, err)
	assert.Empty(t, result.Webhooks)
	assert.False(t, called)
}

func TestWebhookSecretNeverLeaksIntoResultsOrLogs(t *testing.T) {
	// Security: a receiver failure must report the problem without ever
	// surfacing the shared secret in statuses, JSON results, or logs.
	var logs bytes.Buffer

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	const secret = "super-sensitive-shared-secret"
	cfg := fmt.Sprintf(`
version: 1
default_network: testnet
networks:
  testnet:
    rpc_url: https://rpc.example.org
    passphrase: "Test SDF Network ; September 2015"
    webhooks:
      - url: %s
        secret: %s
contracts:
  counter:
    wasm: ./counter.wasm
`, srv.URL, secret)

	h := newHarness(t, harnessOptions{configBody: cfg, logOut: &logs})

	result, err := h.svc.Deploy(context.Background(), deploy.DeployRequest{Alias: "counter"})
	require.NoError(t, err, "a failing webhook still must not fail the deploy")
	require.Len(t, result.Webhooks, 1)
	assert.False(t, result.Webhooks[0].OK)

	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	for _, leak := range []string{string(encoded), logs.String()} {
		assert.NotContains(t, leak, secret, "the shared secret must never be reported")
	}
}

func TestWebhookRetries5xxAndPreservesIdenticalSignature(t *testing.T) {
	var (
		mu         sync.Mutex
		signatures []string
		bodies     []string
		calls      int
		slept      []time.Duration
	)

	const secret = "retry-hmac-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls++
		attempt := calls
		signatures = append(signatures, r.Header.Get("X-SoroForge-Signature"))
		bodies = append(bodies, string(body))
		mu.Unlock()

		if attempt < 3 {
			http.Error(w, "upstream restarting", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := deploy.NewHTTPWebhookSenderWithOptions(srv.Client(), deploy.WebhookRetryOptions{
		MaxAttempts: 4,
		BaseBackoff: 100 * time.Millisecond,
		MaxBackoff:  2 * time.Second,
		Jitter:      func(d time.Duration) time.Duration { return d },
		Sleep: func(_ context.Context, d time.Duration) error {
			mu.Lock()
			slept = append(slept, d)
			mu.Unlock()
			return nil
		},
	})

	cfg := fmt.Sprintf(`
version: 1
default_network: testnet
networks:
  testnet:
    rpc_url: https://rpc.example.org
    passphrase: "Test SDF Network ; September 2015"
    webhooks:
      - url: %s
        secret: %s
contracts:
  counter:
    wasm: ./counter.wasm
`, srv.URL, secret)

	h := newHarness(t, harnessOptions{configBody: cfg, webhooks: sender})
	result, err := h.svc.Deploy(context.Background(), deploy.DeployRequest{Alias: "counter"})
	require.NoError(t, err)

	require.Len(t, result.Webhooks, 1)
	assert.True(t, result.Webhooks[0].OK)
	assert.Equal(t, 3, result.Webhooks[0].Attempts)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, signatures, 3)
	assert.NotEmpty(t, signatures[0])
	assert.Equal(t, signatures[0], signatures[1], "signature header must be identical across retries")
	assert.Equal(t, signatures[0], signatures[2], "signature header must be identical across retries")
	assert.Equal(t, bodies[0], bodies[1])
	assert.Equal(t, []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}, slept)
}

func TestWebhookDoesNotRetryNon4294xx(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(code)
			}))
			defer srv.Close()

			sender := deploy.NewHTTPWebhookSenderWithOptions(srv.Client(), deploy.WebhookRetryOptions{
				MaxAttempts: 4,
				Sleep: func(_ context.Context, _ time.Duration) error {
					t.Fatal("non-429 4xx must not sleep or retry")
					return nil
				},
			})

			attempts, err := sender.Deliver(context.Background(), config.Webhook{URL: srv.URL}, deploy.WebhookPayload{Alias: "counter"})
			require.Error(t, err)
			assert.Equal(t, 1, attempts)
			assert.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestWebhookHonoursAndCapsRetryAfterOn429And503(t *testing.T) {
	fixedNow := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

	var (
		mu    sync.Mutex
		calls int
		slept []time.Duration
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()

		switch n {
		case 1:
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			// HTTP-date 60s in the future must be capped at MaxBackoff (5s).
			w.Header().Set("Retry-After", fixedNow.Add(60*time.Second).Format(http.TimeFormat))
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	sender := deploy.NewHTTPWebhookSenderWithOptions(srv.Client(), deploy.WebhookRetryOptions{
		MaxAttempts: 4,
		MaxBackoff:  5 * time.Second,
		Now:         func() time.Time { return fixedNow },
		Sleep: func(_ context.Context, d time.Duration) error {
			mu.Lock()
			slept = append(slept, d)
			mu.Unlock()
			return nil
		},
	})

	attempts, err := sender.Deliver(context.Background(), config.Webhook{URL: srv.URL}, deploy.WebhookPayload{Alias: "counter"})
	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
	assert.Equal(t, []time.Duration{2 * time.Second, 5 * time.Second}, slept)
}

func TestWebhookRetriesNetworkErrorsAndBoundsTotalTime(t *testing.T) {
	// Closed server produces immediate transport errors that must be retried up to MaxAttempts.
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	deadURL := deadSrv.URL
	deadSrv.Close()

	var sleeps int
	sender := deploy.NewHTTPWebhookSenderWithOptions(nil, deploy.WebhookRetryOptions{
		MaxAttempts: 3,
		Sleep: func(_ context.Context, _ time.Duration) error {
			sleeps++
			return nil
		},
	})

	attempts, err := sender.Deliver(context.Background(), config.Webhook{URL: deadURL}, deploy.WebhookPayload{Alias: "counter"})
	require.Error(t, err)
	assert.Equal(t, 3, attempts)
	assert.Equal(t, 2, sleeps)

	// A stalled receiver cannot block beyond TotalTimeout.
	releaseHandler := make(chan struct{})
	stalledSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-releaseHandler:
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(releaseHandler)
		stalledSrv.Close()
	}()

	bounded := deploy.NewHTTPWebhookSenderWithOptions(&http.Client{Timeout: 5 * time.Second}, deploy.WebhookRetryOptions{
		MaxAttempts:  4,
		TotalTimeout: 40 * time.Millisecond,
	})

	start := time.Now()
	_, err = bounded.Deliver(context.Background(), config.Webhook{URL: stalledSrv.URL}, deploy.WebhookPayload{Alias: "counter"})
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Less(t, elapsed, 500*time.Millisecond, "total delivery time must be bounded by TotalTimeout")
}
