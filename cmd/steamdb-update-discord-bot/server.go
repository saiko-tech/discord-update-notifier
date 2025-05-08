package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type Server struct {
	bot    *Bot
	server *http.Server
}

func NewServer(bot *Bot) *Server {
	return &Server{
		bot: bot,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/_healthz", s.handleHealth)

	s.server = &http.Server{
		Addr:    httpAddr,
		Handler: mux,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.S().Fatalw("error running HTTP server", "error", err)
		}
	}()

	return nil
}

func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("error shutting down HTTP server: %v", err)
		}
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check Discord connection
	if s.bot.session.State == nil || s.bot.session.State.User == nil {
		http.Error(w, "Discord connection not ready", http.StatusServiceUnavailable)
		return
	}

	// Check config access
	s.bot.config.mu.RLock()
	configOK := s.bot.config != nil
	s.bot.config.mu.RUnlock()

	if !configOK {
		http.Error(w, "Config not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}
