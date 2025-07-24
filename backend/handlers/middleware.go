package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
)

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

const SessionContextKey ContextKey = "session"

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

// getSession retrieves the current session from a request cookie.
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
		h.Store.DeleteSession(r.Context(), cookie.Value)
		return nil
	}

	return session
}
