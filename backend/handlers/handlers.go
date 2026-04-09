// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fkcurrie/utba-swarmmap/service"
	"github.com/fkcurrie/utba-swarmmap/store"
	"golang.org/x/oauth2"
)

type Handlers struct {
	Store             store.Storer
	SwarmService      service.SwarmService
	LocationService   LocationService
	GoogleOAuthConfig *oauth2.Config
	AppleOAuthConfig  *oauth2.Config
	Version           string
	Templates         *template.Template
	FrontendAssetsURL string
	MapboxToken       string
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
	slog.Debug("IndexHandler called", "path", h.sanitize(r.URL.Path)) // #nosec G706
	if r.URL.Path != "/" {
		slog.Debug("Path not /, returning NotFound", "path", h.sanitize(r.URL.Path)) // #nosec G706
		http.NotFound(w, r)
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
	if r.Method != http.MethodGet {
		h.jsonError(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
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
