package api

import (
	"context"
	"embed"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/adithyan-ak/agenthound/server/internal/api/handlers"
	apimw "github.com/adithyan-ak/agenthound/server/internal/api/middleware"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed all:ui/dist
var uiFS embed.FS

type Server struct {
	router     *chi.Mux
	httpServer *http.Server
}

type ServerDeps struct {
	GraphDB     graph.GraphDB
	Reader      *graph.Reader
	PGPool      *pgxpool.Pool
	Pipeline    *ingest.Pipeline
	ScanStore   *appdb.ScanStore
	RulesEngine *rules.Engine
	CORSOrigins []string
	// LocalToken gates all mutating endpoints with a Bearer token. The
	// embedded UI fetches the token from /api/v1/auth/local-token on
	// load. Required; callers should construct via apimw.NewLocalToken.
	LocalToken *apimw.LocalToken
}

func NewServer(deps ServerDeps) *Server {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(apimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(apimw.CORS(deps.CORSOrigins))

	healthH := handlers.NewHealthHandler(deps.Reader, deps.PGPool)
	graphH := handlers.NewGraphHandler(deps.Reader)
	ingestH := handlers.NewIngestHandler(deps.Pipeline)
	queryH := handlers.NewQueryHandler(deps.Reader)
	analysisH := handlers.NewAnalysisHandler(deps.GraphDB)
	scanH := handlers.NewScanHandler(deps.ScanStore, deps.GraphDB)
	rulesH := handlers.NewRulesHandler(deps.RulesEngine)

	r.Route("/api/v1", func(r chi.Router) {
		// Open read endpoints. Single-user posture means localhost
		// reads are fine; gating them would force the UI to plumb
		// auth headers through every TanStack Query for no security
		// gain.
		r.Get("/health", healthH.Handle)
		r.Get("/docs", handlers.HandleOpenAPIDocs)

		// auth/local-token is the bootstrap path the embedded UI uses
		// to discover the token. Same-origin is enforced via CORS
		// (AllowCredentials: false, AllowedOrigins allowlist).
		if deps.LocalToken != nil {
			r.Get("/auth/local-token", apimw.LocalTokenHandler(deps.LocalToken))
		}

		r.Get("/graph/stats", graphH.HandleStats)
		r.Get("/graph/search", graphH.HandleSearch)
		r.Get("/graph/nodes", graphH.HandleListNodes)
		r.Get("/graph/nodes/{id}", graphH.HandleGetNode)
		r.Get("/graph/nodes/{id}/neighborhood", graphH.HandleNeighborhood)
		r.Get("/graph/nodes/{id}/blast-radius", graphH.HandleBlastRadius)
		r.Get("/graph/edges", graphH.HandleListEdges)

		r.Get("/analysis/findings", analysisH.HandleFindings)
		r.Get("/analysis/findings/{id}", analysisH.HandleFindingDetail)
		r.Get("/analysis/prebuilt", analysisH.HandleListPreBuilt)
		r.Get("/analysis/prebuilt/{id}", analysisH.HandlePreBuilt)

		r.Get("/scans", scanH.HandleList)
		r.Get("/scans/{id}", scanH.HandleGet)

		r.Get("/rules", rulesH.HandleList)
		r.Get("/rules/{id}", rulesH.HandleGet)

		// Gated mutating endpoints. The localtoken middleware
		// requires Authorization: Bearer <token>. CLI tools (ingest,
		// query) bypass HTTP entirely by calling the pipeline /
		// reader directly — no token needed for CLI use.
		gate := passThrough
		if deps.LocalToken != nil {
			gate = deps.LocalToken.Middleware
		}

		r.Group(func(r chi.Router) {
			r.Use(gate)
			r.Post("/ingest", ingestH.Handle)
			r.Post("/query", queryH.Handle)
			r.Post("/scans", scanH.HandleCreate)
			r.Delete("/scans/{id}", scanH.HandleDelete)
			r.Post("/analysis/shortest-path", analysisH.HandleShortestPath)
			r.Post("/analysis/all-paths", analysisH.HandleAllPaths)
			r.Post("/analysis/weighted-path", analysisH.HandleWeightedPath)
		})
	})

	uiContent, _ := fs.Sub(uiFS, "ui/dist")
	fileServer := http.FileServer(http.FS(uiContent))

	r.Handle("/assets/*", fileServer)
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		f, err := uiContent.Open(req.URL.Path[1:])
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, req)
			return
		}
		index, err := uiContent.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		defer index.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.Copy(w, index)
	})

	return &Server{router: r}
}

// passThrough is the no-op middleware used when no LocalToken is
// configured (test setups). Production always wires a LocalToken.
func passThrough(next http.Handler) http.Handler {
	return next
}

// ListenAndServe binds the HTTP server to the given host:port string.
// Default in agenthound-server is 127.0.0.1:8080 — set explicitly to
// 0.0.0.0:8080 only when the operator has independent network protection.
func (s *Server) ListenAndServe(bind string) error {
	s.httpServer = &http.Server{
		Addr:         bind,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 180 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	slog.Info("starting API server", "bind", bind)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
