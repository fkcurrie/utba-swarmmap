package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

func (h *Handlers) LoginPageHandler(w http.ResponseWriter, _ *http.Request) {
	err := h.Templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"Title":             "Login",
		"Version":           h.Version,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		log.Printf("Error rendering login page: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handlers) RegisterPageHandler(w http.ResponseWriter, _ *http.Request) {
	err := h.Templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
		"Title":             "Register",
		"Version":           h.Version,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		log.Printf("Error rendering register page: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handlers) UsernameLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	ctx := r.Context()
	user, err := h.Store.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("Error getting user by email: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if user == nil || user.PasswordHash == "" {
		h.renderLoginPageWithError(w, "Invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		h.renderLoginPageWithError(w, "Invalid email or password")
		return
	}

	if !user.EmailVerified {
		h.renderLoginPageWithError(w, "Email not verified. Please check your email for the verification link.")
		return
	}

	if user.Status != "approved" {
		showPendingApprovalPage(w, user.Name)
		return
	}

	h.createSessionAndRedirect(w, r, user)
}

func (h *Handlers) UsernameRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	name := r.FormValue("name")
	phone := r.FormValue("phone")
	location := r.FormValue("location")

	ctx := r.Context()
	existingUser, err := h.Store.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if existingUser != nil {
		h.renderRegisterPageWithError(w, "User with this email already exists")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	verificationToken := uuid.New().String()

	user := models.User{
		Email:             email,
		Name:              name,
		Phone:             phone,
		Location:          location,
		Role:              "collector",
		Status:            "pending",
		PasswordHash:      string(hashedPassword),
		EmailVerified:     false,
		VerificationToken: verificationToken,
		CreatedAt:         time.Now(),
	}

	_, err = h.Store.CreateUser(ctx, user)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// In a real app, send an email with the verification link.
	// For this exercise, we'll just log it.
	log.Printf("USER CREATED: %s. VERIFICATION LINK: /auth/verify-email?token=%s", email, verificationToken)

	h.renderMessagePage(w, "Registration Successful", "Your account has been created. Please check your email (see logs) to verify your account.")
}

func (h *Handlers) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	user, err := h.Store.GetUserByVerificationToken(ctx, token)
	if err != nil {
		log.Printf("Error getting user by verification token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	err = h.Store.UpdateUserFields(ctx, user.ID, map[string]interface{}{
		"email_verified":     true,
		"verification_token": "",
	})
	if err != nil {
		log.Printf("Error updating user email verification: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderMessagePage(w, "Email Verified", "Your email has been verified. You can now log in.")
}

func (h *Handlers) createSessionAndRedirect(w http.ResponseWriter, r *http.Request, user *models.User) {
	session := models.Session{
		UserID:    user.ID,
		Username:  user.Email,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	sessionID, err := h.Store.CreateSession(r.Context(), session)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handlers) renderLoginPageWithError(w http.ResponseWriter, errorMsg string) {
	_ = h.Templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"Title":             "Login",
		"Version":           h.Version,
		"Error":             errorMsg,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
}

func (h *Handlers) renderRegisterPageWithError(w http.ResponseWriter, errorMsg string) {
	_ = h.Templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
		"Title":             "Register",
		"Version":           h.Version,
		"Error":             errorMsg,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
}

func (h *Handlers) renderMessagePage(w http.ResponseWriter, title, message string) {
	html := `<!DOCTYPE html><html><head><title>` + title + ` - UTBA Swarm Map</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"></head>
<body><div class="container mt-5"><div class="row justify-content-center"><div class="col-md-6">
<div class="card"><div class="card-header"><h4>` + title + `</h4></div>
<div class="card-body"><div class="alert alert-info"><p>` + message + `</p></div>
<a href="/login" class="btn btn-primary">Return to Login</a></div></div></div></div></div></body></html>`
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(html))
}

func (h *Handlers) GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()
	url := h.GoogleOAuthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handlers) AppleLoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.AppleOAuthConfig == nil {
		http.Error(w, "Apple Sign-in not configured", http.StatusNotImplemented)
		return
	}
	state := uuid.New().String()
	url := h.AppleOAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handlers) AppleCallbackHandler(w http.ResponseWriter, _ *http.Request) {
	// Simplified Apple Callback for now
	http.Error(w, "Apple Callback not fully implemented", http.StatusNotImplemented)
}

func (h *Handlers) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_ = h.Templates.ExecuteTemplate(w, "forgot-password.html", map[string]interface{}{
			"Title":             "Forgot Password",
			"Version":           h.Version,
			"FrontendAssetsURL": h.FrontendAssetsURL,
		})
		return
	}

	email := r.FormValue("email")
	ctx := r.Context()
	user, err := h.Store.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("Error getting user by email: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if user != nil {
		resetToken := uuid.New().String()
		expiresAt := time.Now().Add(1 * time.Hour)

		err = h.Store.UpdateUserFields(ctx, user.ID, map[string]interface{}{
			"reset_token":            resetToken,
			"reset_token_expires_at": expiresAt,
		})
		if err != nil {
			log.Printf("Error updating user reset token: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		log.Printf("PASSWORD RESET REQUESTED: %s. RESET LINK: /auth/reset-password?token=%s", email, resetToken)
	}

	h.renderMessagePage(w, "Reset Email Sent", "If an account exists with that email, a password reset link has been sent.")
}

func (h *Handlers) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		_ = h.Templates.ExecuteTemplate(w, "reset-password.html", map[string]interface{}{
			"Title":             "Reset Password",
			"Version":           h.Version,
			"Token":             token,
			"FrontendAssetsURL": h.FrontendAssetsURL,
		})
		return
	}

	password := r.FormValue("password")
	ctx := r.Context()
	user, err := h.Store.GetUserByResetToken(ctx, token)
	if err != nil {
		log.Printf("Error getting user by reset token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if user == nil || user.ResetTokenExpiresAt.Before(time.Now()) {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = h.Store.UpdateUserFields(ctx, user.ID, map[string]interface{}{
		"password_hash":          string(hashedPassword),
		"reset_token":            "",
		"reset_token_expires_at": time.Time{},
	})
	if err != nil {
		log.Printf("Error updating user password: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("PASSWORD RESET SUCCESSFUL for %s", user.Email)

	h.renderMessagePage(w, "Password Reset Successful", "Your password has been reset. You can now log in with your new password.")
}

func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		_ = h.Store.DeleteSession(r.Context(), cookie.Value)
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
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": false})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"user":          session,
	})
}

func (h *Handlers) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

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
	defer func() { _ = resp.Body.Close() }()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("Failed to decode user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	existingUser, err := h.Store.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		log.Printf("Failed to query user: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if existingUser == nil {
		user := models.User{
			Email:         userInfo.Email,
			Name:          userInfo.Name,
			Role:          "collector",
			Status:        "pending",
			EmailVerified: true, // Google emails are already verified
			CreatedAt:     time.Now(),
		}

		_, err = h.Store.CreateUser(ctx, user)
		if err != nil {
			log.Printf("Failed to create user: %v", err)
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		showPendingApprovalPage(w, userInfo.Name)
		return
	}

	if existingUser.Status != "approved" {
		showPendingApprovalPage(w, existingUser.Name)
		return
	}

	h.createSessionAndRedirect(w, r, existingUser)
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
	_, _ = w.Write([]byte(html))
}
