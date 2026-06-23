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

// uiFallbackFS is a tiny "UI not built" page that ships in every server
// binary. It's served only when ui/dist is empty — i.e. when someone built
// the binary without running `make ui-build` first. It's a separate embed
// so the build pipeline (which clears ui/dist) can never overwrite it.
//
//go:embed ui/fallback/index.html
var uiFallbackFS embed.FS

type Server struct {
	router     *chi.Mux
	httpServer *http.Server
}

type ServerDeps struct {
	GraphDB      graph.GraphDB
	Reader       *graph.Reader
	PGPool       *pgxpool.Pool
	Pipeline     *ingest.Pipeline
	ScanStore    *appdb.ScanStore
	FindingStore *appdb.FindingStore
	RulesEngine  *rules.Engine
	// CORSOrigins is the allowlist for both the CORS preflight handler
	// and OriginGuard on mutating endpoints. Default is set in servercfg.
	CORSOrigins []string
}

func NewServer(deps ServerDeps) *Server {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	// RealIP intentionally omitted: it rewrites RemoteAddr from spoofable
	// X-Forwarded-For / X-Real-IP headers (GHSA-3fxj-6jh8-hvhx). The server
	// is localhost-only and nothing reads RemoteAddr, so it adds spoofing
	// surface for zero benefit.
	r.Use(apimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(apimw.CORS(deps.CORSOrigins))

	healthH := handlers.NewHealthHandler(deps.Reader, deps.PGPool)
	graphH := handlers.NewGraphHandler(deps.Reader)
	ingestH := handlers.NewIngestHandler(deps.Pipeline)
	queryH := handlers.NewQueryHandler(deps.Reader)
	analysisH := handlers.NewAnalysisHandler(deps.GraphDB, deps.FindingStore)
	scanH := handlers.NewScanHandler(deps.ScanStore, deps.GraphDB)
	rulesH := handlers.NewRulesHandler(deps.RulesEngine)
	triageH := handlers.NewTriageHandler(deps.FindingStore)

	r.Route("/api/v1", func(r chi.Router) {
		// Open read endpoints. Single-user posture means localhost
		// reads are fine; gating them would force the UI to plumb
		// auth headers through every TanStack Query for no security
		// gain.
		r.Get("/health", healthH.Handle)
		r.Get("/docs", handlers.HandleOpenAPIDocs)

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

		// Triage read is open (same posture as findings reads); the
		// mutating PUT is gated below.
		r.Get("/findings/triage/{fingerprint}", triageH.HandleGet)

		r.Get("/scans", scanH.HandleList)
		r.Get("/scans/{id}", scanH.HandleGet)

		r.Get("/rules", rulesH.HandleList)
		r.Get("/rules/{id}", rulesH.HandleGet)

		// Gated mutating endpoints. OriginGuard rejects browser
		// requests from origins outside the allowlist (drive-by CSRF
		// defense). Non-browser callers (curl, the agenthound CLI,
		// cron pipelines) send no Origin header and pass through.
		r.Group(func(r chi.Router) {
			r.Use(apimw.OriginGuard(deps.CORSOrigins))
			r.Post("/ingest", ingestH.Handle)
			r.Post("/query", queryH.Handle)
			r.Post("/scans", scanH.HandleCreate)
			r.Delete("/scans/{id}", scanH.HandleDelete)
			r.Post("/analysis/shortest-path", analysisH.HandleShortestPath)
			r.Post("/analysis/all-paths", analysisH.HandleAllPaths)
			r.Post("/analysis/weighted-path", analysisH.HandleWeightedPath)
			r.Put("/findings/triage/{fingerprint}", triageH.HandleSet)
		})
	})

	uiContent, _ := fs.Sub(uiFS, "ui/dist")
	fileServer := http.FileServer(http.FS(uiContent))

	// distHasIndex is the signal that the React UI was actually built into
	// this binary. If false, the binary was compiled with only the dist
	// marker file present — serve the embedded fallback page instead.
	distHasIndex := false
	if f, err := uiContent.Open("index.html"); err == nil {
		f.Close()
		distHasIndex = true
	}

	r.Handle("/assets/*", fileServer)
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		if distHasIndex {
			f, err := uiContent.Open(req.URL.Path[1:])
			if err == nil {
				f.Close()
				fileServer.ServeHTTP(w, req)
				return
			}
			index, err := uiContent.Open("index.html")
			if err == nil {
				defer index.Close()
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = io.Copy(w, index)
				return
			}
		}
		fallback, err := uiFallbackFS.Open("ui/fallback/index.html")
		if err != nil {
			http.Error(w, "ui not available", http.StatusInternalServerError)
			return
		}
		defer fallback.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.Copy(w, fallback)
	})

	return &Server{router: r}
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
