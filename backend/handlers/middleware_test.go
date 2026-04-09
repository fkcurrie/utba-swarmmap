// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
)

func TestSecurityHeaders(t *testing.T) {
	h := &Handlers{}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := h.SecurityHeaders(nextHandler)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", rr.Code)
	}

	headers := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	}

	for _, header := range headers {
		if rr.Header().Get(header) == "" {
			t.Errorf("expected header %s to be set", header)
		}
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("expected CSP to contain frame-ancestors 'none', got %s", csp)
	}
}

func TestVerifyCSRF(t *testing.T) {
	h := &Handlers{}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := h.VerifyCSRF(nextHandler)

	t.Run("GET request bypasses CSRF", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected status OK for GET, got %v", rr.Code)
		}
	})

	t.Run("POST request without session bypasses CSRF (as currently implemented)", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected status OK for POST without session, got %v", rr.Code)
		}
	})

	t.Run("POST request with session and valid token in header", func(t *testing.T) {
		session := &models.Session{
			UserID:    "user1",
			CSRFToken: "token123",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		ctx := context.WithValue(context.Background(), SessionContextKey, session)
		req := httptest.NewRequest("POST", "/", nil)
		req = req.WithContext(ctx)
		req.Header.Set("X-CSRF-Token", "token123")
		
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected status OK with valid token, got %v", rr.Code)
		}
	})

	t.Run("POST request with session and valid token in form", func(t *testing.T) {
		session := &models.Session{
			UserID:    "user1",
			CSRFToken: "token123",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		ctx := context.WithValue(context.Background(), SessionContextKey, session)
		req := httptest.NewRequest("POST", "/", strings.NewReader("csrf_token=token123"))
		req = req.WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected status OK with valid form token, got %v", rr.Code)
		}
	})

	t.Run("POST request with session and missing token", func(t *testing.T) {
		session := &models.Session{
			UserID:    "user1",
			CSRFToken: "token123",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		ctx := context.WithValue(context.Background(), SessionContextKey, session)
		req := httptest.NewRequest("POST", "/", nil)
		req = req.WithContext(ctx)
		
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status Forbidden with missing token, got %v", rr.Code)
		}
	})

	t.Run("POST request with session and invalid token", func(t *testing.T) {
		session := &models.Session{
			UserID:    "user1",
			CSRFToken: "token123",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		ctx := context.WithValue(context.Background(), SessionContextKey, session)
		req := httptest.NewRequest("POST", "/", nil)
		req = req.WithContext(ctx)
		req.Header.Set("X-CSRF-Token", "wrong-token")
		
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status Forbidden with invalid token, got %v", rr.Code)
		}
	})
}
