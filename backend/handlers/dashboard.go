// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"log/slog"
	"net/http"

	"github.com/fkcurrie/utba-swarmmap/models"
)

func (h *Handlers) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	allSwarms, err := h.Store.GetAllSwarms(r.Context())
	if err != nil {
		slog.Error("Error getting all swarms for dashboard", "error", err)
		http.Error(w, "Failed to retrieve swarms", http.StatusInternalServerError)
		return
	}

	availableSwarms := []models.SwarmReport{}
	assignedSwarms := []models.SwarmReport{}

	for _, swarm := range allSwarms {
		if swarm.AssignedCollectorID == session.UserID {
			assignedSwarms = append(assignedSwarms, swarm)
		} else if swarm.AssignedCollectorID == "" && (swarm.Status == "Reported" || swarm.Status == "Verified") {
			availableSwarms = append(availableSwarms, swarm)
		}
	}

	// Determine navigation options based on role
	showCollectorAdmin := session.Role == "collector_admin" || session.Role == "site_admin"
	showSiteAdmin := session.Role == "site_admin"

	err = h.Templates.ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Title":              "Dashboard",
		"Version":            h.Version,
		"BuildDate":          h.BuildDate,
		"User":               session,
		"AvailableSwarms":    availableSwarms,
		"AssignedSwarms":     assignedSwarms,
		"ShowCollectorAdmin": showCollectorAdmin,
		"ShowSiteAdmin":      showSiteAdmin,
		"FrontendAssetsURL":  h.FrontendAssetsURL,
		"MapboxToken":        h.MapboxToken,
	})
	if err != nil {
		slog.Error("Error executing dashboard template", "error", err)
		http.Error(w, "Failed to parse dashboard template", http.StatusInternalServerError)
		return
	}
}
