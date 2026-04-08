package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/internal/api/handlers"
	apimw "github.com/adithyan-ak/agenthound/internal/api/middleware"
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/ingest"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	router     *chi.Mux
	httpServer *http.Server
}

func NewServer(reader *graph.Reader, pgPool *pgxpool.Pool, pipeline *ingest.Pipeline) *Server {
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

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", healthH.Handle)
		r.Get("/graph/stats", graphH.HandleStats)
		r.Get("/graph/nodes", graphH.HandleListNodes)
		r.Get("/graph/nodes/{id}", graphH.HandleGetNode)
		r.Get("/graph/edges", graphH.HandleListEdges)
		r.Post("/ingest", ingestH.Handle)
		r.Post("/query", queryH.Handle)
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
