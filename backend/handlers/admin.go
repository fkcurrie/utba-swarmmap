// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

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
		"MapboxToken":       h.MapboxToken,
	})
	if err != nil {
		slog.Error("Error executing admin template", "error", err)
		http.Error(w, "Failed to parse admin template", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) BootstrapHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	allUsers, err := h.Store.GetAllUsers(ctx)
	if err != nil {
		slog.Error("Error checking for existing users during bootstrap", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Safety check: Disable bootstrap if at least one site_admin exists
	for _, user := range allUsers {
		if user.Role == "site_admin" {
			slog.Warn("Bootstrap attempted but site_admin already exists", "adminEmail", h.sanitize(user.Email))
			http.Error(w, "Bootstrap is disabled because an administrator already exists.", http.StatusForbidden)
			return
		}
	}

	if r.Method == http.MethodGet {
		err := h.Templates.ExecuteTemplate(w, "bootstrap.html", map[string]interface{}{
			"Title":             "Bootstrap Admin",
			"Version":           h.Version,
			"FrontendAssetsURL": h.FrontendAssetsURL,
		})
		if err != nil {
			slog.Error("Error rendering bootstrap page", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Handle POST
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // Limit body to 1MB
	name := r.FormValue("name")
	email := r.FormValue("email")

	if name == "" || email == "" {
		err := h.Templates.ExecuteTemplate(w, "bootstrap.html", map[string]interface{}{
			"Title":             "Bootstrap Admin",
			"Version":           h.Version,
			"Error":             "Name and Email are required",
			"FrontendAssetsURL": h.FrontendAssetsURL,
		})
		if err != nil {
			slog.Error("Error rendering bootstrap page with error", "error", err)
		}
		return
	}

	newUser := models.User{
		Email:         email,
		Name:          name,
		Role:          "site_admin",
		Status:        "approved",
		EmailVerified: true,
		CreatedAt:     time.Now(),
	}

	_, err = h.Store.CreateUser(ctx, newUser)
	if err != nil {
		slog.Error("Failed to create bootstrap admin", "error", err, "email", h.sanitize(email)) // #nosec G706
		http.Error(w, "Failed to create admin user", http.StatusInternalServerError)
		return
	}

	slog.Info("INITIAL ADMIN BOOTSTRAPPED", "name", h.sanitize(name), "email", h.sanitize(email)) // #nosec G706

	err = h.Templates.ExecuteTemplate(w, "bootstrap.html", map[string]interface{}{
		"Title":             "Bootstrap Admin",
		"Version":           h.Version,
		"Success":           fmt.Sprintf("Administrator %s (%s) has been created successfully.", name, email),
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error rendering bootstrap page with success", "error", err)
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
		slog.Error("Failed to approve user", "error", err, "userID", h.sanitize(userID)) // #nosec G706
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
		slog.Error("Failed to reject user", "error", err, "userID", h.sanitize(userID)) // #nosec G706
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
		slog.Error("Failed to delete swarm", "error", err, "swarmID", h.sanitize(swarmID)) // #nosec G706
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
		slog.Error("Failed to promote user", "error", err, "userID", h.sanitize(userID), "newRole", h.sanitize(newRole)) // #nosec G706
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
		"MapboxToken":       h.MapboxToken,
	})
	if err != nil {
		slog.Error("Error executing collector admin template", "error", err)
		http.Error(w, "Failed to parse collector admin template", http.StatusInternalServerError)
		return
	}
}
