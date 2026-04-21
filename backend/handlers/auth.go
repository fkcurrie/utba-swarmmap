// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// LoginPageHandler renders the login page.
func (h *Handlers) LoginPageHandler(w http.ResponseWriter, _ *http.Request) {
	err := h.Templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"Title":             "Login",
		"Version":           h.Version,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error rendering login page", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// RegisterPageHandler renders the registration page.
func (h *Handlers) RegisterPageHandler(w http.ResponseWriter, _ *http.Request) {
	err := h.Templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
		"Title":             "Register",
		"Version":           h.Version,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error rendering register page", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// UsernameLoginHandler handles login requests with username and password.
func (h *Handlers) UsernameLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB

	email := r.FormValue("email")
	password := r.FormValue("password")

	ctx := r.Context()
	user, err := h.Store.GetUserByEmail(ctx, email)
	if err != nil {
		slog.Error("Error getting user by email", "error", err, "email", h.sanitize(email)) // #nosec G706
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
		h.showPendingApprovalPage(w, user.Name)
		return
	}

	h.createSessionAndRedirect(w, r, user)
}

// UsernameRegisterHandler handles registration requests with username and password.
func (h *Handlers) UsernameRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB

	email := r.FormValue("email")
	password := r.FormValue("password")
	name := r.FormValue("name")
	phone := r.FormValue("phone")
	location := r.FormValue("location")
	experienceYearsStr := r.FormValue("experience_years")
	equipment := r.FormValue("equipment")
	competencyNotes := r.FormValue("competency_notes")

	experienceYears, _ := strconv.Atoi(experienceYearsStr)

	ctx := r.Context()
	existingUser, err := h.Store.GetUserByEmail(ctx, email)
	if err != nil {
		slog.Error("Error checking existing user", "error", err, "email", h.sanitize(email)) // #nosec G706
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if existingUser != nil {
		h.renderRegisterPageWithError(w, "User with this email already exists")
		return
	}

	if len(password) < 8 {
		h.renderRegisterPageWithError(w, "Password must be at least 8 characters long")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Error hashing password", "error", err)
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
		ExperienceYears:   experienceYears,
		Equipment:         equipment,
		CompetencyNotes:   competencyNotes,
	}

	_, err = h.Store.CreateUser(ctx, user)
	if err != nil {
		slog.Error("Error creating user", "error", err, "email", h.sanitize(email)) // #nosec G706
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// In a real app, send an email with the verification link.
	// For this exercise, we'll just log it.
	slog.Info("USER CREATED", "email", h.sanitize(email), "verificationToken", h.sanitize(verificationToken)) // #nosec G706

	// Send notification to admins
	h.sendAdminNotification(user)

	h.renderMessagePage(w, "Application Submitted", "Your application has been submitted successfully. Please check your email (see logs) to verify your account. An administrator will review your application soon.")
}

func (h *Handlers) sendAdminNotification(user models.User) {
	// For this implementation, we will log the "email" content.
	// In a production environment, this would use net/smtp to send a real email.
	subject := "New Collector Access Request"
	body := "A new collector access request has been submitted.\n\n" +
		"Name: " + user.Name + "\n" +
		"Email: " + user.Email + "\n" +
		"Location: " + user.Location + "\n" +
		"Experience: " + strconv.Itoa(user.ExperienceYears) + " years\n" +
		"Equipment: " + user.Equipment + "\n" +
		"Competency: " + user.CompetencyNotes + "\n\n" +
		"Review application here: /admin"

	slog.Info("ADMIN NOTIFICATION EMAIL",
		"subject", subject,
		"to", "admin@example.com", // In real app, fetch from config/db
		"userID", user.ID,
		"body", body,
	)
}

// VerifyEmailHandler handles email verification with a token.
func (h *Handlers) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	user, err := h.Store.GetUserByVerificationToken(ctx, token)
	if err != nil {
		slog.Error("Error getting user by verification token", "error", err, "token", h.sanitize(token)) // #nosec G706
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
		slog.Error("Error updating user email verification", "error", err, "userID", h.sanitize(user.ID)) // #nosec G706
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
		slog.Error("Failed to create session", "error", err, "userID", h.sanitize(user.ID)) // #nosec G706
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
	err := h.Templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"Title":             "Login",
		"Version":           h.Version,
		"Error":             errorMsg,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error rendering login page with error", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) renderRegisterPageWithError(w http.ResponseWriter, errorMsg string) {
	err := h.Templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
		"Title":             "Register",
		"Version":           h.Version,
		"Error":             errorMsg,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error rendering register page with error", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) renderMessagePage(w http.ResponseWriter, title, message string) {
	err := h.Templates.ExecuteTemplate(w, "message.html", map[string]interface{}{
		"Title":             title,
		"Message":           message,
		"Version":           h.Version,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error rendering message page", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) showPendingApprovalPage(w http.ResponseWriter, name string) {
	err := h.Templates.ExecuteTemplate(w, "pending-approval.html", map[string]interface{}{
		"Name":              name,
		"Version":           h.Version,
		"FrontendAssetsURL": h.FrontendAssetsURL,
	})
	if err != nil {
		slog.Error("Error rendering pending approval page", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (h *Handlers) GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GoogleLoginHandler called", "path", h.sanitize(r.URL.Path)) // #nosec G706
	state := uuid.New().String()

	// Store state in a cookie to verify it in the callback
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	url := h.GoogleOAuthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account"))
	slog.Debug("Redirecting to Google Auth", "url", h.sanitize(url)) // #nosec G706
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// AppleLoginHandler initiates the Apple OAuth2 login flow.
func (h *Handlers) AppleLoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.AppleOAuthConfig == nil {
		http.Error(w, "Apple Sign-in not configured", http.StatusNotImplemented)
		return
	}
	state := uuid.New().String()

	// Store state in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	url := h.AppleOAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// AppleCallbackHandler handles the callback from Apple OAuth2.
func (h *Handlers) AppleCallbackHandler(w http.ResponseWriter, _ *http.Request) {
	// Simplified Apple Callback for now
	http.Error(w, "Apple Callback not fully implemented", http.StatusNotImplemented)
}

// ForgotPasswordHandler handles password reset requests.
func (h *Handlers) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		err := h.Templates.ExecuteTemplate(w, "forgot-password.html", map[string]interface{}{
			"Title":             "Forgot Password",
			"Version":           h.Version,
			"FrontendAssetsURL": h.FrontendAssetsURL,
		})
		if err != nil {
			slog.Error("Error rendering forgot-password page", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB

	email := r.FormValue("email")

	ctx := r.Context()
	user, err := h.Store.GetUserByEmail(ctx, email)
	if err != nil {
		slog.Error("Error getting user by email", "error", err, "email", h.sanitize(email)) // #nosec G706
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
			slog.Error("Error updating user reset token", "error", err, "email", h.sanitize(email)) // #nosec G706
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		slog.Info("PASSWORD RESET REQUESTED", "email", h.sanitize(email), "resetToken", h.sanitize(resetToken)) // #nosec G706
	}

	h.renderMessagePage(w, "Reset Email Sent", "If an account exists with that email, a password reset link has been sent.")
}

// ResetPasswordHandler handles the actual password reset.
func (h *Handlers) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		err := h.Templates.ExecuteTemplate(w, "reset-password.html", map[string]interface{}{
			"Title":             "Reset Password",
			"Version":           h.Version,
			"Token":             token,
			"FrontendAssetsURL": h.FrontendAssetsURL,
		})
		if err != nil {
			slog.Error("Error rendering reset-password page", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB

	password := r.FormValue("password")
	ctx := r.Context()

	user, err := h.Store.GetUserByResetToken(ctx, token)
	if err != nil {
		slog.Error("Error getting user by reset token", "error", err, "token", h.sanitize(token)) // #nosec G706
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if user == nil || user.ResetTokenExpiresAt.Before(time.Now()) {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	if len(password) < 8 {
		err := h.Templates.ExecuteTemplate(w, "reset-password.html", map[string]interface{}{
			"Title":             "Reset Password",
			"Version":           h.Version,
			"Token":             token,
			"Error":             "Password must be at least 8 characters long",
			"FrontendAssetsURL": h.FrontendAssetsURL,
		})
		if err != nil {
			slog.Error("Error rendering reset-password page with error", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Error hashing password", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = h.Store.UpdateUserFields(ctx, user.ID, map[string]interface{}{
		"password_hash":          string(hashedPassword),
		"reset_token":            "",
		"reset_token_expires_at": time.Time{},
	})
	if err != nil {
		slog.Error("Error updating user password", "error", err, "email", h.sanitize(user.Email)) // #nosec G706
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	slog.Info("PASSWORD RESET SUCCESSFUL", "email", h.sanitize(user.Email)) // #nosec G706

	h.renderMessagePage(w, "Password Reset Successful", "Your password has been reset. You can now log in with your new password.")
}

// LogoutHandler logs out the user by deleting their session.
func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		if err := h.Store.DeleteSession(r.Context(), cookie.Value); err != nil {
			slog.Error("Failed to delete session", "error", err)
		}
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

// AuthHandler checks the user's authentication status and returns it as JSON.
func (h *Handlers) AuthHandler(w http.ResponseWriter, r *http.Request) {
	session := h.getSession(r)
	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": false}); err != nil {
			slog.Error("Failed to encode auth response", "error", err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"user":          session,
	}); err != nil {
		slog.Error("Failed to encode auth response", "error", err)
	}
}

// GoogleCallbackHandler handles the callback from Google OAuth2.
func (h *Handlers) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Verify state to prevent CSRF
	cookie, err := r.Cookie("oauth_state")
	if err != nil || cookie == nil || cookie.Value == "" || cookie.Value != state {
		expected := ""
		if cookie != nil {
			expected = cookie.Value
		}
		slog.Warn("Invalid OAuth state", "expected", h.sanitize(expected), "actual", h.sanitize(state)) // #nosec G706
		http.Error(w, "Invalid state parameter", http.StatusUnauthorized)
		return
	}

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	ctx := r.Context()
	token, err := h.GoogleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		slog.Error("Failed to exchange code for token", "error", err)
		http.Error(w, "Failed to authenticate", http.StatusInternalServerError)
		return
	}

	client := h.GoogleOAuthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		slog.Error("Failed to get user info", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		slog.Error("Failed to decode user info", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	existingUser, err := h.Store.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		slog.Error("Failed to query user", "error", err, "email", h.sanitize(userInfo.Email)) // #nosec G706
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
			slog.Error("Failed to create user", "error", err, "email", h.sanitize(userInfo.Email)) // #nosec G706
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		h.showPendingApprovalPage(w, userInfo.Name)
		return
	}

	if existingUser.Status != "approved" {
		h.showPendingApprovalPage(w, existingUser.Name)
		return
	}

	h.createSessionAndRedirect(w, r, existingUser)
}
