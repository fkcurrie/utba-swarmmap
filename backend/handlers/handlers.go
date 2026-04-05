package handlers

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/fkcurrie/utba-swarmmap/store"
	"golang.org/x/oauth2"
)

type Handlers struct {
	Store             store.Storer
	GoogleOAuthConfig *oauth2.Config
	AppleOAuthConfig  *oauth2.Config
	Version           string
	Templates         *template.Template
	FrontendAssetsURL string
}

func (h *Handlers) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
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

func (h *Handlers) GetSwarmsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.jsonError(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	var currentReports []models.SwarmReport
	var err error

	sessionID := r.URL.Query().Get("sessionId")

	if sessionID != "" {
		slog.Info("Fetching swarms for public user session", "sessionId", sessionID)
		currentReports, err = h.Store.GetSwarmsBySessionID(ctx, sessionID)
	} else {
		slog.Info("Fetching all swarms")
		currentReports, err = h.Store.GetAllSwarms(ctx)
	}

	if err != nil {
		slog.Error("Error fetching reports", "error", err)
		h.jsonError(w, "Error fetching reports", http.StatusInternalServerError)
		return
	}

	// Dynamic DisplayStatus logic and privacy filtering
	session := h.getSession(r)
	isCollector := session != nil && (session.Role == "collector" || session.Role == "collector_admin" || session.Role == "site_admin")

	for i := range currentReports {
		currentReports[i].DisplayStatus = currentReports[i].Status
		if currentReports[i].Status != "Captured" && time.Since(currentReports[i].ReportedTimestamp).Hours() > 24 {
			currentReports[i].DisplayStatus = "Archived"
		}

		// Privacy: Clear reporter details if not a collector/admin
		if !isCollector {
			currentReports[i].ReporterName = ""
			currentReports[i].ReporterEmail = ""
			currentReports[i].ReporterPhone = ""
			currentReports[i].ReporterSessionID = ""
		}
	}

	slog.Info("Returning swarms", "count", len(currentReports), "isCollector", isCollector)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(currentReports); err != nil {
		slog.Error("Error encoding reports to JSON", "error", err)
	}
}
