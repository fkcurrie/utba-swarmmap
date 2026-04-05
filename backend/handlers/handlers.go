package handlers

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/fkcurrie/utba-swarmmap/service"
	"github.com/fkcurrie/utba-swarmmap/store"
	"golang.org/x/oauth2"
)

type Handlers struct {
	Store             store.Storer
	SwarmService      service.SwarmService
	GoogleOAuthConfig *oauth2.Config
	AppleOAuthConfig  *oauth2.Config
	Version           string
	Templates         *template.Template
	FrontendAssetsURL string
}

func (h *Handlers) IndexHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("IndexHandler called", "path", r.URL.Path)
	if r.URL.Path != "/" {
		slog.Debug("Path not /, returning NotFound", "path", r.URL.Path)
		http.NotFound(w, r)
		return
	}

	session := h.getSession(r)

	err := h.Templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Title":             "Home",
		"Version":           h.Version,
		"User":              session,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error executing template", "error", err)
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func (h *Handlers) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		slog.Error("Failed to encode JSON error", "error", err)
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
		slog.Error("Error fetching reports from service", "error", err)
		h.jsonError(w, "Error fetching reports", http.StatusInternalServerError)
		return
	}

	slog.Info("Returning swarms", "count", len(currentReports))
	data, err := json.Marshal(currentReports)
	if err != nil {
		slog.Error("Error marshalling reports to JSON", "error", err)
		h.jsonError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		slog.Error("Failed to write swarms response", "error", err)
	}
}
