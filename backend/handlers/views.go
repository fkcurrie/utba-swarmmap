package handlers

import (
	"log"
	"net/http"

	"github.com/fkcurrie/utba-swarmmap/models"
)

func (h *Handlers) SwarmListHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		http.Error(w, "Could not retrieve session from context", http.StatusInternalServerError)
		return
	}

	swarms, err := h.Store.GetAllSwarms(r.Context())
	if err != nil {
		http.Error(w, "Failed to retrieve swarms", http.StatusInternalServerError)
		return
	}

	err = h.Templates.ExecuteTemplate(w, "swarmlist.html", map[string]interface{}{
		"Title":             "Swarm List",
		"Swarms":            swarms,
		"Version":           h.Version,
		"User":              session,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		log.Printf("Error executing swarm list template: %v", err)
		http.Error(w, "Failed to render swarm list", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) CollectorsMapHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		// This should not happen if RequireAuth is used, but as a safeguard:
		http.Error(w, "Could not retrieve session from context", http.StatusInternalServerError)
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
		log.Printf("Error executing collectors_map.html template: %v", err)
		http.Error(w, "Failed to render collector map", http.StatusInternalServerError)
	}
}
