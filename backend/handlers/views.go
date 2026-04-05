package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
)

func (h *Handlers) SwarmListHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	swarms, err := h.Store.GetAllSwarms(r.Context())
	if err != nil {
		slog.Error("Failed to retrieve swarms", "error", err)
		http.Error(w, "Failed to retrieve swarms", http.StatusInternalServerError)
		return
	}

	// Dynamic DisplayStatus logic
	for i := range swarms {
		swarms[i].DisplayStatus = swarms[i].Status
		if swarms[i].Status != "Captured" && time.Since(swarms[i].ReportedTimestamp).Hours() > 24 {
			swarms[i].DisplayStatus = "Archived"
		}
	}

	err = h.Templates.ExecuteTemplate(w, "swarmlist.html", map[string]interface{}{
		"Title":             "Swarm List",
		"Swarms":            swarms,
		"Version":           h.Version,
		"User":              session,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error executing swarm list template", "error", err)
		http.Error(w, "Failed to render swarm list", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) CollectorsMapHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		// This should not happen if RequireAuth is used, but as a safeguard:
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title":             "Collectors Map",
		"Version":           h.Version,
		"User":              session,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	}

	err := h.Templates.ExecuteTemplate(w, "collectors_map.html", data)
	if err != nil {
		slog.Error("Error executing collectors_map.html template", "error", err)
		http.Error(w, "Failed to render collector map", http.StatusInternalServerError)
	}
}
