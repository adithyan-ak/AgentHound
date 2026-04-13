package api

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/internal/api/handlers"
	apimw "github.com/adithyan-ak/agenthound/internal/api/middleware"
	"github.com/adithyan-ak/agenthound/internal/appdb"
	"github.com/adithyan-ak/agenthound/internal/audit"
	"github.com/adithyan-ak/agenthound/internal/auth"
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/ingest"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
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
	UserStore   *appdb.UserStore
	TokenStore  *appdb.TokenStore
	AuditStore  *appdb.AuditStore
	JWTSecret   string
	CORSOrigins []string
}

func NewServer(deps ServerDeps) *Server {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(apimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(apimw.CORS(deps.CORSOrigins))
	r.Use(httprate.LimitByIP(100, time.Minute))

	auditLog := audit.NewLogger(deps.AuditStore)

	healthH := handlers.NewHealthHandler(deps.Reader, deps.PGPool)
	graphH := handlers.NewGraphHandler(deps.Reader)
	ingestH := handlers.NewIngestHandler(deps.Pipeline, auditLog)
	queryH := handlers.NewQueryHandler(deps.Reader, auditLog)
	analysisH := handlers.NewAnalysisHandler(deps.GraphDB, auditLog)
	scanH := handlers.NewScanHandler(deps.ScanStore, deps.GraphDB, auditLog)
	authH := handlers.NewAuthHandler(deps.UserStore, deps.TokenStore, deps.JWTSecret, auditLog)
	auditH := handlers.NewAuditHandler(deps.AuditStore)

	authMW := auth.NewMiddleware(deps.JWTSecret, deps.TokenStore, deps.UserStore)

	r.Route("/api/v1", func(r chi.Router) {
		// Public routes
		r.Get("/health", healthH.Handle)
		r.Get("/docs", handlers.HandleOpenAPIDocs)
		r.Post("/auth/login", authH.HandleLogin)

		// Authenticated routes — viewer+
		r.Group(func(r chi.Router) {
			r.Use(authMW.Authenticate)
			r.Use(auth.RequireRole(auth.RoleViewer))

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
		})

		// Authenticated routes — analyst+
		r.Group(func(r chi.Router) {
			r.Use(authMW.Authenticate)
			r.Use(auth.RequireRole(auth.RoleAnalyst))

			r.With(httprate.LimitByIP(20, time.Minute)).Post("/ingest", ingestH.Handle)
			r.Post("/scans", scanH.HandleCreate)
			r.Delete("/scans/{id}", scanH.HandleDelete)
			r.Post("/analysis/shortest-path", analysisH.HandleShortestPath)
			r.Post("/analysis/all-paths", analysisH.HandleAllPaths)
			r.Post("/analysis/weighted-path", analysisH.HandleWeightedPath)
			r.Post("/auth/tokens", authH.HandleCreateToken)
			r.Get("/auth/tokens", authH.HandleListTokens)
			r.Delete("/auth/tokens/{id}", authH.HandleDeleteToken)
		})

		// Authenticated routes — admin only
		r.Group(func(r chi.Router) {
			r.Use(authMW.Authenticate)
			r.Use(auth.RequireRole(auth.RoleAdmin))

			r.With(httprate.LimitByIP(10, time.Minute)).Post("/query", queryH.Handle)
			r.Post("/auth/users", authH.HandleCreateUser)
			r.Get("/auth/users", authH.HandleListUsers)
			r.Delete("/auth/users/{id}", authH.HandleDeleteUser)
			r.Get("/audit", auditH.HandleList)
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

func (s *Server) ListenAndServe(port int) error {
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 180 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	slog.Info("starting API server", "port", port)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
