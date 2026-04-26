// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
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

		// Only set HSTS if not on localhost
		if !strings.HasPrefix(r.Host, "localhost") && !strings.HasPrefix(r.Host, "127.0.0.1") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Content Security Policy
		// Allow self, Google Fonts, FontAwesome, Mapbox, and Nominatim fallback
		assetsURL := ""
		if h.FrontendAssetsURL != "" {
			assetsURL = " " + h.FrontendAssetsURL
		}

		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' blob: https://api.mapbox.com https://*.mapbox.com" + assetsURL + "; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://api.mapbox.com https://*.mapbox.com" + assetsURL + "; " +
			"font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://api.mapbox.com https://*.mapbox.com" + assetsURL + "; " +
			"img-src 'self' data: blob: https://api.mapbox.com https://*.mapbox.com https://*.tiles.mapbox.com https://*.googleapis.com https://*.gstatic.com" + assetsURL + "; " +
			"connect-src 'self' https://nominatim.openstreetmap.org https://api.mapbox.com https://*.mapbox.com https://*.tiles.mapbox.com https://events.mapbox.com" + assetsURL + "; " +
			"worker-src 'self' blob: https://api.mapbox.com https://*.mapbox.com" + assetsURL + "; " +
			"child-src 'self' blob: https://api.mapbox.com https://*.mapbox.com" + assetsURL + "; " +
			"media-src 'self' https://*.googleapis.com" + assetsURL + "; " +
			"frame-ancestors 'none';"

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

// WithSession is a middleware that populates the session in the context if it exists, but does not require it.
func (h *Handlers) WithSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := h.getSession(r)
		if session != nil {
			ctx := context.WithValue(r.Context(), SessionContextKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
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

		// Limit request body size to 1MB to prevent memory exhaustion (G120)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		session, ok := r.Context().Value(SessionContextKey).(*models.Session)
		if !ok || session == nil {
			// If no session, we might still want to check CSRF for public forms
			// For now, only enforced for authenticated routes.
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			// Explicitly parse form to satisfy G120
			if err := r.ParseForm(); err != nil {
				slog.Debug("Error parsing form in VerifyCSRF", "error", err)
			}
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
