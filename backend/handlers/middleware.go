// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
)

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

const SessionContextKey ContextKey = "session"

// SecurityHeaders is a middleware that adds security-related headers to the response.
func (h *Handlers) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Content Security Policy
		// Allow self, Google Fonts, FontAwesome, OpenStreetMap tiles, and Nominatim
		csp := "default-src 'self'; " +
			"script-src 'self' https://cdn.jsdelivr.net; " +
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
			"font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
			"img-src 'self' data: https://*.tile.openstreetmap.org https://*.googleapis.com https://*.gstatic.com; " +
			"connect-src 'self' https://nominatim.openstreetmap.org;"

		w.Header().Set("Content-Security-Policy", csp)

		next.ServeHTTP(w, r)
	})
}

// RequireAuth is a middleware that checks for a valid session.
func (h *Handlers) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := h.getSession(r)
		if session == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Add session to context for downstream handlers
		ctx := context.WithValue(r.Context(), SessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handlers) RequireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := r.Context().Value(SessionContextKey).(*models.Session)
		if !ok {
			// This should not happen if RequireAuth is used first, but as a safeguard:
			slog.Error("Could not retrieve session from context")
			http.Error(w, "Could not retrieve session from context", http.StatusInternalServerError)
			return
		}

		// Role hierarchy: site_admin can access everything
		if session.Role == "site_admin" {
			next.ServeHTTP(w, r)
			return
		}

		// collector_admin can access collector management functions
		if session.Role == "collector_admin" && (role == "collector_admin" || role == "collector") {
			next.ServeHTTP(w, r)
			return
		}

		// Regular role check
		if session.Role == role {
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

// VerifyCSRF is a middleware that checks for a valid CSRF token in POST requests.
func (h *Handlers) VerifyCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		session, ok := r.Context().Value(SessionContextKey).(*models.Session)
		if !ok || session == nil {
			// If no session, we might still want to check CSRF for public forms
			// For now, only enforced for authenticated routes.
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.FormValue("csrf_token")
		}

		if token == "" || token != session.CSRFToken {
			slog.Warn("CSRF token mismatch or missing", "userID", h.sanitize(session.UserID)) // #nosec G706
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
func (h *Handlers) getSession(r *http.Request) *models.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	session, err := h.Store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		if err := h.Store.DeleteSession(r.Context(), cookie.Value); err != nil {
			slog.Error("Failed to delete expired session", "error", err)
		}
		return nil
	}

	return session
}
