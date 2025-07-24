package handlers

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/fkcurrie/utba-swarmmap/store"
	"golang.org/x/oauth2"
)

type Handlers struct {
	Store             store.Storer
	GoogleOAuthConfig *oauth2.Config
	Version           string
	Templates         *template.Template
	FrontendAssetsURL string
}

func (h *Handlers) IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
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
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func (h *Handlers) GetSwarmsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	var currentReports []models.SwarmReport
	var err error

	sessionID := r.URL.Query().Get("sessionId")

	if sessionID != "" {
		log.Printf("Fetching swarms for public user session: %s", sessionID)
		currentReports, err = h.Store.GetSwarmsBySessionID(ctx, sessionID)
	} else {
		log.Printf("Fetching all swarms")
		currentReports, err = h.Store.GetAllSwarms(ctx)
	}

	if err != nil {
		log.Printf("Error fetching reports: %v", err)
		http.Error(w, "Error fetching reports", http.StatusInternalServerError)
		return
	}

	// Dynamic DisplayStatus logic
	for i := range currentReports {
		currentReports[i].DisplayStatus = currentReports[i].Status
		if currentReports[i].Status != "Captured" && time.Since(currentReports[i].ReportedTimestamp).Hours() > 24 {
			currentReports[i].DisplayStatus = "Archived"
		}
	}

	log.Printf("Returning %d swarms", len(currentReports))
	data, err := json.Marshal(currentReports)
	if err != nil {
		log.Printf("Error marshalling reports to JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}