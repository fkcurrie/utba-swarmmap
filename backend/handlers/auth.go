package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func (h *Handlers) GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()
	// Add prompt=select_account to force Google account chooser
	url := h.GoogleOAuthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		h.Store.DeleteSession(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handlers) AuthHandler(w http.ResponseWriter, r *http.Request) {
	session := h.getSession(r)
	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": false})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"user":          session,
	})
}

func (h *Handlers) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Verify state parameter exists and is valid (basic check)
	if state == "" {
		http.Error(w, "Invalid state parameter", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	token, err := h.GoogleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		http.Error(w, "Failed to authenticate", http.StatusInternalServerError)
		return
	}

	client := h.GoogleOAuthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("Failed to decode user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Check if user already exists
	existingUser, err := h.Store.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		log.Printf("Failed to query user: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if existingUser == nil {
		// User doesn't exist, create new user with pending status
		user := models.User{
			Email:     userInfo.Email,
			Name:      userInfo.Name,
			Role:      "collector",
			Status:    "pending", // Requires admin approval
			CreatedAt: time.Now(),
		}

		_, err = h.Store.CreateUser(ctx, user)
		if err != nil {
			log.Printf("Failed to create user: %v", err)
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		// Show pending approval message
		showPendingApprovalPage(w, userInfo.Name)
		return
	}

	if existingUser.Status != "approved" {
		showPendingApprovalPage(w, existingUser.Name)
		return
	}

	// User is approved, create session and log them in
	session := models.Session{
		UserID:    existingUser.ID,
		Username:  existingUser.Email,
		Role:      existingUser.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	sessionID, err := h.Store.CreateSession(ctx, session)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   true, // Required for HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func showPendingApprovalPage(w http.ResponseWriter, name string) {
	html := `<!DOCTYPE html>
<html><head><title>Pending Approval - UTBA Swarm Map</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"></head>
<body><div class="container mt-5"><div class="row justify-content-center"><div class="col-md-6">
<div class="card"><div class="card-header"><h4>Account Pending Approval</h4></div>
<div class="card-body"><div class="alert alert-info">
<h6>Hello ` + name + `!</h6>
<p>Your account has been created and is pending administrator approval.</p>
<p>A UTBA administrator will review your request and approve your access to the swarm collector dashboard.</p>
<p>You'll be able to log in once your account has been approved.</p>
</div>
<a href="/" class="btn btn-primary">Return to Map</a></div></div></div></div></div></body></html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
