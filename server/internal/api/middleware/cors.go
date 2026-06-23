package middleware

import (
	"net/http"

	"github.com/go-chi/cors"
)

// CORS configures cross-origin sharing for the AgentHound API.
//
// AllowCredentials is intentionally false. The server has no
// application-layer credentials to send. The actual CSRF defense lives
// in OriginGuard, which gates mutating endpoints on the same allowlist.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:8080"}
	}
	return cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	})
}
