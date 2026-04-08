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
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/ingest"
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

func NewServer(graphDB graph.GraphDB, reader *graph.Reader, pgPool *pgxpool.Pool, pipeline *ingest.Pipeline, scanStore *appdb.ScanStore) *Server {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(apimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(apimw.CORS())

	healthH := handlers.NewHealthHandler(reader, pgPool)
	graphH := handlers.NewGraphHandler(reader)
	ingestH := handlers.NewIngestHandler(pipeline)
	queryH := handlers.NewQueryHandler(reader)
	analysisH := handlers.NewAnalysisHandler(graphDB)
	scanH := handlers.NewScanHandler(scanStore)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", healthH.Handle)
		r.Get("/graph/stats", graphH.HandleStats)
		r.Get("/graph/nodes", graphH.HandleListNodes)
		r.Get("/graph/nodes/{id}", graphH.HandleGetNode)
		r.Get("/graph/edges", graphH.HandleListEdges)
		r.Post("/ingest", ingestH.Handle)
		r.Post("/query", queryH.Handle)

		r.Post("/analysis/shortest-path", analysisH.HandleShortestPath)
		r.Post("/analysis/all-paths", analysisH.HandleAllPaths)
		r.Post("/analysis/weighted-path", analysisH.HandleWeightedPath)
		r.Get("/analysis/findings", analysisH.HandleFindings)
		r.Get("/analysis/prebuilt", analysisH.HandleListPreBuilt)
		r.Get("/analysis/prebuilt/{id}", analysisH.HandlePreBuilt)

		r.Get("/scans", scanH.HandleList)
		r.Get("/scans/{id}", scanH.HandleGet)
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
		io.Copy(w, index)
	})

	return &Server{router: r}
}

func (s *Server) ListenAndServe(port int) error {
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
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
