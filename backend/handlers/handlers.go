// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fkcurrie/utba-swarmmap/service"
	"github.com/fkcurrie/utba-swarmmap/store"
	"golang.org/x/oauth2"
)

type AIService interface {
	InterpretFeedback(ctx context.Context, rawText string, feedbackType string, context FeedbackContext) (string, error)
}

type Handlers struct {
	Store             store.Storer
	SwarmService      service.SwarmService
	LocationService   LocationService
	GitHubService     GitHubService
	AIService         AIService
	GoogleOAuthConfig *oauth2.Config
	AppleOAuthConfig  *oauth2.Config
	Version           string
	Templates         *template.Template
	FrontendAssetsURL string
	MapboxToken       string
	GithubToken       string
	GithubRepo        string
}

func (h *Handlers) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		slog.Error("Failed to encode JSON error response", "error", err, "message", h.sanitize(message)) // #nosec G706
	}
}

func (h *Handlers) sanitize(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
}

func (h *Handlers) IndexHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("IndexHandler called", "method", r.Method, "path", h.sanitize(r.URL.Path)) // #nosec G706
	
	// Normalize path and check if it's the root.
	// We allow empty path or "/" to be handled as root for maximum robustness.
	p := r.URL.Path
	if p == "" {
		p = "/"
	}

	if p != "/" {
		slog.Debug("Path not root, returning NotFound", "path", h.sanitize(p)) // #nosec G706
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	session := h.getSession(r)

	err := h.Templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Title":             "Home",
		"Version":           h.Version,
		"User":              session,
		"FrontendAssetsURL": h.FrontendAssetsURL,
		"MapboxToken":       h.MapboxToken,
	})
	if err != nil {
		slog.Error("Error executing template", "error", err) // #nosec G706
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) GetSwarmsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		h.jsonError(w, "Only GET and HEAD methods are allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	sessionID := r.URL.Query().Get("sessionId")
	session := h.getSession(r)

	currentReports, err := h.SwarmService.GetSwarms(ctx, sessionID, session)
	if err != nil {
		slog.Error("Error fetching reports from service", "error", err) // #nosec G706
		h.jsonError(w, "Error fetching reports", http.StatusInternalServerError)
		return
	}

	slog.Info("Returning swarms", "count", len(currentReports)) // #nosec G706
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(currentReports); err != nil {
		slog.Error("Error encoding reports to JSON", "error", err) // #nosec G706
	}
}
