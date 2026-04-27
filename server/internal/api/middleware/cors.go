package middleware

import (
	"net/http"

	"github.com/go-chi/cors"
)

// CORS configures cross-origin sharing for the AgentHound API.
//
// AllowCredentials is intentionally false. Combined with the localhost
// token requirement on mutating endpoints, this defends the server from
// drive-by browser attackers: a hostile origin cannot ride the
// operator's ambient cookies, and cannot read the token endpoint
// because the response is non-credentialed.
//
// The server has no application-layer credentials to send anyway, so
// nothing breaks.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:8080"}
	}
	return cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	})
}
