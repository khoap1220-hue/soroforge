package deploy

import (
	"context"

	"github.com/soroworks/soroforge/internal/netcheck"
)

// CheckNetworks probes every configured network's RPC endpoint concurrently
// using the service's client factory, returning one credential-redacted report
// per network sorted by name.
func (s *Service) CheckNetworks(ctx context.Context) []netcheck.Result {
	return netcheck.Check(ctx, s.cfg.Networks, netcheck.ClientFactory(s.clients), 0)
}
