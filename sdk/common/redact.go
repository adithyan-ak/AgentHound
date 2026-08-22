package common

// Redact returns a non-reversible prefix of a secret for safe logging:
// the first 8 characters followed by "..." for values longer than 8
// characters, or "***" for anything 8 characters or shorter (where an
// 8-char prefix would expose too large a fraction of the secret).
//
// Service collectors use this only for diagnostic logging. Graph output and
// the scan artifact intentionally retain concrete Credential values.
func Redact(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:8] + "..."
}
