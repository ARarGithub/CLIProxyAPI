package executor

import (
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"

	"github.com/google/uuid"
)

// derivePerAuthSessionID returns a session_id derived from (originalID, auth.ID).
//
// Why: when the auth selector hands a mid-session request to a different OAuth
// account (rate-limit fallback, InvalidateAuth, etc.), forwarding the original
// session_id unchanged lets upstream correlate two account credentials onto the
// same session — a decisive pool fingerprint. Re-deriving per auth keeps the
// id stable within one account (so OpenAI's per-account prompt cache still
// hits) and changes it across accounts (so cross-account correlation fails).
// See LEAK_RISKS.md L1.
//
// Returns originalID unchanged when auth or auth.ID is empty.
func derivePerAuthSessionID(originalID string, auth *cliproxyauth.Auth) string {
	originalID = strings.TrimSpace(originalID)
	if originalID == "" {
		return ""
	}
	if auth == nil {
		return originalID
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return originalID
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(originalID+":"+authID)).String()
}
