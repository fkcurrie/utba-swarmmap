package handlers

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"cloud.google.com/go/firestore"
	"github.com/fkcurrie/utba-swarmmap/models"
)

func (h *Handlers) AdminHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		http.Error(w, "Could not retrieve session from context", http.StatusInternalServerError)
		return
	}

	allUsers, err := h.Store.GetAllUsers(r.Context())
	if err != nil {
		log.Printf("Error getting all users: %v", err)
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	allSwarms, err := h.Store.GetAllSwarms(r.Context())
	if err != nil {
		log.Printf("Error getting all swarms: %v", err)
		http.Error(w, "Failed to retrieve swarms", http.StatusInternalServerError)
		return
	}

	var pendingUsers []models.User
	for _, user := range allUsers {
		if user.Status == "pending" {
			pendingUsers = append(pendingUsers, user)
		}
	}

	var reportedSwarms, capturedSwarms int
	for _, swarm := range allSwarms {
		if swarm.Status == "Reported" {
			reportedSwarms++
		}
		if swarm.Status == "Captured" {
			capturedSwarms++
		}
	}

	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "7d"
	}
	days := 7 // Default to 7 days
	switch rangeStr {
	case "24h":
		days = 1
	case "30d":
		days = 30
	case "60d":
		days = 60
	case "6m":
		days = 180
	case "12m":
		days = 365
	}

	visits, err := h.Store.GetVisitCounts(r.Context(), days)
	if err != nil {
		log.Printf("Error getting visit counts: %v", err)
		// We can choose to fail silently here and just not show the visits
		visits = make(map[string]int)
	}

	// Convert map to JSON for easy use in JavaScript
	visitsJSON, err := json.Marshal(visits)
	if err != nil {
		log.Printf("Error marshalling visits to JSON: %v", err)
		http.Error(w, "Failed to process visit data", http.StatusInternalServerError)
		return
	}

	err = h.Templates.ExecuteTemplate(w, "admin.html", map[string]interface{}{
		"Title":             "Admin Dashboard",
		"Version":           h.Version,
		"User":              session,
		"PendingUsers":      pendingUsers,
		"AllUsers":          allUsers,
		"AllSwarms":         allSwarms,
		"ReportedSwarms":    reportedSwarms,
		"CapturedSwarms":    capturedSwarms,
		"VisitsJSON":        template.JS(visitsJSON), // Pass as JavaScript-safe string
		"FrontendAssetsURL": h.FrontendAssetsURL,
		"CurrentRange":      rangeStr,
	})
	if err != nil {
		log.Printf("Error executing admin template: %v", err)
		http.Error(w, "Failed to parse admin template", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) ApproveUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.FormValue("userID")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	updates := []firestore.Update{
		{Path: "status", Value: "approved"},
	}
	if err := h.Store.UpdateUser(r.Context(), userID, updates); err != nil {
		log.Printf("Failed to approve user %s: %v", userID, err)
		http.Error(w, "Failed to approve user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handlers) RejectUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.FormValue("userID")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	if err := h.Store.DeleteUser(r.Context(), userID); err != nil {
		log.Printf("Failed to reject user %s: %v", userID, err)
		http.Error(w, "Failed to reject user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handlers) DeleteSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	swarmID := r.FormValue("swarmID")
	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}

	if err := h.Store.DeleteSwarm(r.Context(), swarmID); err != nil {
		log.Printf("Failed to delete swarm %s: %v", swarmID, err)
		http.Error(w, "Failed to delete swarm", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handlers) PromoteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.FormValue("userID")
	newRole := r.FormValue("role")

	if userID == "" || newRole == "" {
		http.Error(w, "User ID and role required", http.StatusBadRequest)
		return
	}

	validRoles := map[string]bool{
		"collector":       true,
		"collector_admin": true,
		"site_admin":      true,
	}
	if !validRoles[newRole] {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	updates := []firestore.Update{
		{Path: "role", Value: newRole},
	}
	if err := h.Store.UpdateUser(r.Context(), userID, updates); err != nil {
		log.Printf("Failed to promote user %s to %s: %v", userID, newRole, err)
		http.Error(w, "Failed to promote user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handlers) CollectorAdminHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		http.Error(w, "Could not retrieve session from context", http.StatusInternalServerError)
		return
	}

	// In a real implementation, we would fetch users here.
	// For now, we'll just render the template.
	err := h.Templates.ExecuteTemplate(w, "collector_admin.html", map[string]interface{}{
		"Title":             "Collector Admin",
		"Version":           h.Version,
		"User":              session,
		"PendingUsers":      nil,
		"AllCollectors":     nil,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		log.Printf("Error executing collector admin template: %v", err)
		http.Error(w, "Failed to parse collector admin template", http.StatusInternalServerError)
		return
	}
}
