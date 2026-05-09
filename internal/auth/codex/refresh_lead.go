package codex

import (
	"math/rand"
	"time"
)

// RefreshLeadMin / RefreshLeadMax bound the random window used to schedule
// proactive Codex token refresh. The default 5d lead in the upstream SDK is
// fingerprintable: every account refreshes at exactly expiry-5d. Randomizing
// inside [RefreshLeadMin, RefreshLeadMax] spreads the refresh times across
// accounts and across cycles, making it harder for upstream to spot the pool.
//
// See LEAK_RISKS.md A2/A4.
const (
	RefreshLeadMin = 3 * 24 * time.Hour
	RefreshLeadMax = 7 * 24 * time.Hour
)

// NextRefreshLead returns a random duration in [RefreshLeadMin, RefreshLeadMax].
//
// Persistence: the caller is expected to write the rolled value to
// auth.Metadata["refresh_interval_seconds"] after a successful refresh, so
// future scheduling reads the persisted value via the SDK's
// authPreferredInterval path and does not re-roll on restart. This prevents
// the "frequent docker restart converges to maxLead" failure mode.
func NextRefreshLead() time.Duration {
	return RefreshLeadMin + time.Duration(rand.Int63n(int64(RefreshLeadMax-RefreshLeadMin)))
}
