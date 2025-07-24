package handlers

import (
	"log"
	"net/http"

	"github.com/fkcurrie/utba-swarmmap/models"
)

func (h *Handlers) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		http.Error(w, "Could not retrieve session from context", http.StatusInternalServerError)
		return
	}

	// In a real implementation, we would fetch available and assigned swarms here.
	// For now, we'll just render the template with the user's session.
	availableSwarms := []models.SwarmReport{}
	assignedSwarms := []models.SwarmReport{}

	// Determine navigation options based on role
	showCollectorAdmin := session.Role == "collector_admin" || session.Role == "site_admin"
	showSiteAdmin := session.Role == "site_admin"

	err := h.Templates.ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Title":              "Dashboard",
		"Version":            h.Version,
		"User":               session,
		"AvailableSwarms":    availableSwarms,
		"AssignedSwarms":     assignedSwarms,
		"ShowCollectorAdmin": showCollectorAdmin,
		"ShowSiteAdmin":      showSiteAdmin,
		"FrontendAssetsURL":  h.FrontendAssetsURL,
	})
	if err != nil {
		log.Printf("Error executing dashboard template: %v", err)
		http.Error(w, "Failed to parse dashboard template", http.StatusInternalServerError)
		return
	}
}
