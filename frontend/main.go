// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package main

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// getEnv reads an environment variable with a fallback value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	// Initialize slog with JSON handler
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	portStr := os.Getenv("PORT")
	if portStr == "" {
		portStr = "8080"
	}

	// Sanitize port to avoid log injection warning (CWE-117).
	// Validating that it is a number and then re-converting to string
	// is a strong way to ensure no malicious characters are present.
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		// If port is invalid, we fatal for clarity on configuration error.
		slog.Error("Invalid PORT environment variable", "error", err, "port", strings.ReplaceAll(strings.ReplaceAll(portStr, "\n", ""), "\r", "")) // #nosec G706
		os.Exit(1)
	}

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("./static"))
	
	// Add CORS headers for static assets (especially fonts)
	staticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.StripPrefix("/static/", fs).ServeHTTP(w, r)
	})
	
	mux.Handle("/static/", staticHandler)

	// Health and utility routes
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	slog.Info("Listening", "port", portInt) // #nosec G706

	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(portInt),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
