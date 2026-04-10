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
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	if !strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("expected CSP to contain 'unsafe-inline' in script-src, got %s", csp)
	}
	if !strings.Contains(csp, "blob:") {
		t.Errorf("expected CSP to contain blob:, got %s", csp)
	}
	if !strings.Contains(csp, "font-src 'self' data:") {
		t.Errorf("expected CSP to contain font-src 'self' data:, got %s", csp)
	}
	if !strings.Contains(csp, "https://api.mapbox.com") {
		t.Errorf("expected CSP to contain https://api.mapbox.com, got %s", csp)
	}
	if !strings.Contains(csp, "https://*.mapbox.com") {
		t.Errorf("expected CSP to contain https://*.mapbox.com, got %s", csp)
	}
	if !strings.Contains(csp, "https://unpkg.com") {
		t.Errorf("expected CSP to contain https://unpkg.com, got %s", csp)
	}
	if !strings.Contains(csp, "https://events.mapbox.com") {
		t.Errorf("expected CSP to contain https://events.mapbox.com, got %s", csp)
	}
	if !strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("expected CSP to contain 'unsafe-eval', got %s", csp)
	}
	if !strings.Contains(csp, "worker-src 'self' blob:") {
		t.Errorf("expected CSP to contain worker-src 'self' blob:, got %s", csp)
	}
	if !strings.Contains(csp, "media-src 'self' https://*.googleapis.com") {
		t.Errorf("expected CSP to contain media-src 'self' https://*.googleapis.com, got %s", csp)
	}

	t.Run("CSP with FrontendAssetsURL", func(t *testing.T) {
		h2 := &Handlers{FrontendAssetsURL: "https://assets.example.com"}
		handler2 := h2.SecurityHeaders(nextHandler)
		rr2 := httptest.NewRecorder()
		handler2.ServeHTTP(rr2, req)
		csp2 := rr2.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp2, "https://assets.example.com") {
			t.Errorf("expected CSP to contain https://assets.example.com, got %s", csp2)
		}
		// Verify it's in multiple directives
		directives := []string{"script-src", "style-src", "font-src", "img-src", "connect-src", "worker-src", "child-src", "media-src"}
		for _, d := range directives {
			if !strings.Contains(csp2, d) || !strings.Contains(strings.Split(csp2, d)[1], "https://assets.example.com") {
				t.Errorf("expected %s to contain https://assets.example.com in %s", d, csp2)
			}
		}
	})
}

func TestVerifyCSRF(t *testing.T) {
	h := &Handlers{}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
