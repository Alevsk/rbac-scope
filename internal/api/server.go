package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// Server represents the API server
type Server struct {
	router *mux.Router
}

// NewServer creates a new API server instance
func NewServer() *Server {
	s := &Server{
		router: mux.NewRouter(),
	}
	s.routes()
	return s
}

// routes sets up the API routes
func (s *Server) routes() {
	s.router.HandleFunc("/api/v1/health", s.healthCheck).Methods("GET")
}

// Start starts the API server
func (s *Server) Start(addr string) error {
	log.Printf("Starting server on %s", addr)
	return http.ListenAndServe(addr, s.router)
}

// healthCheck handles the health check endpoint
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	}); err != nil {
		log.Printf("Failed to encode health check response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
