package common

// Redact returns a non-reversible prefix of a secret for safe logging:
// the first 8 characters followed by "..." for values longer than 8
// characters, or "***" for anything 8 characters or shorter (where an
// 8-char prefix would expose too large a fraction of the secret).
//
// Two production call sites depend on this:
//
//   - Looters route operator-supplied keys through Redact() before any
//     slog call so a full credential never lands in a log file or SIEM
//     (see modules/litellmloot/looter.go, modules/openwebuiloot/looter.go).
//   - The CLI command layer routes raw --credential input through
//     Redact() when formatting error messages (see
//     collector/cli/loot.go). A malformed flag value (e.g. `--credential
//     sk-...` without an `=`) would otherwise surface the raw secret to
//     stderr twice — once via Cobra's RunE error surface, once via
//     collector/cmd/agenthound/main.go — and end up in whichever pipe
//     the operator wired stderr into.
func Redact(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:8] + "..."
}
