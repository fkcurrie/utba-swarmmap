package handlers

import (
	"log/slog"
	"net/http"

	"cloud.google.com/go/firestore"
	"github.com/fkcurrie/utba-swarmmap/models"
)

func (h *Handlers) AdminHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	allUsers, err := h.Store.GetAllUsers(r.Context())
	if err != nil {
		slog.Error("Error getting all users", "error", err)
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	allSwarms, err := h.Store.GetAllSwarms(r.Context())
	if err != nil {
		slog.Error("Error getting all swarms", "error", err)
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
		slog.Error("Error getting visit counts", "error", err)
		// We can choose to fail silently here and just not show the visits
		visits = make(map[string]int)
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
		"VisitCounts":       visits,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error executing admin template", "error", err)
		http.Error(w, "Failed to parse admin template", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) ApproveUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Limit body to 1MB
	userID := r.FormValue("userID")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	updates := []firestore.Update{
		{Path: "status", Value: "approved"},
	}
	if err := h.Store.UpdateUser(r.Context(), userID, updates); err != nil {
		slog.Error("Failed to approve user", "error", err, "userID", userID)
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Limit body to 1MB
	userID := r.FormValue("userID")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	if err := h.Store.DeleteUser(r.Context(), userID); err != nil {
		slog.Error("Failed to reject user", "error", err, "userID", userID)
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Limit body to 1MB
	swarmID := r.FormValue("swarmID")
	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}

	if err := h.Store.DeleteSwarm(r.Context(), swarmID); err != nil {
		slog.Error("Failed to delete swarm", "error", err, "swarmID", swarmID)
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Limit body to 1MB
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
		slog.Error("Failed to promote user", "error", err, "userID", userID, "newRole", newRole)
		http.Error(w, "Failed to promote user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handlers) CollectorAdminHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		slog.Error("Error executing collector admin template", "error", err)
		http.Error(w, "Failed to parse collector admin template", http.StatusInternalServerError)
		return
	}
}
