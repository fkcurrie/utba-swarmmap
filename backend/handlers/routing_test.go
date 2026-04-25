// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoutingMainConflict(t *testing.T) {
	mux := http.NewServeMux()

	// Legacy pattern (no method)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// New pattern (with method) - Exact match root
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("index"))
	})

	tests := []struct {
		method string
		path   string
		status int
		body   string
	}{
		{"GET", "/", http.StatusOK, "index"},
		{"GET", "/healthz", http.StatusOK, "ok"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != tt.status {
			t.Errorf("%s %s: expected status %d, got %d", tt.method, tt.path, tt.status, rr.Code)
		}
	}
}
