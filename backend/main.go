// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package main

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	"github.com/fkcurrie/utba-swarmmap/handlers"
	"github.com/fkcurrie/utba-swarmmap/service"
	"github.com/fkcurrie/utba-swarmmap/store"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var version = "0.6.0"

// getEnv reads an environment variable with a fallback value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	// Initialize slog with JSON handler
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	ctx := context.Background()
	projectID := getEnv("GCP_PROJECT_ID", "utba-swarmmap")
	bucketName := getEnv("GCS_BUCKET_NAME", "utba-swarmmap-media")

	// Initialize Google OAuth2 configuration
	googleOAuthConfig := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// Initialize Firestore client
	slog.Info("Initializing Firestore client", "projectID", strings.ReplaceAll(strings.ReplaceAll(projectID, "\n", ""), "\r", "")) // #nosec G706
	if host := os.Getenv("FIRESTORE_EMULATOR_HOST"); host != "" {
		slog.Info("Using Firestore Emulator", "host", strings.ReplaceAll(strings.ReplaceAll(host, "\n", ""), "\r", "")) // #nosec G706
	}
	firestoreClient, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		slog.Error("Failed to create Firestore client", "error", err)
		os.Exit(1)
	}
	slog.Info("Firestore client initialized successfully")

	// Initialize Storage client
	slog.Info("Initializing Storage client")
	if host := os.Getenv("STORAGE_EMULATOR_HOST"); host != "" {
		slog.Info("Using Storage Emulator", "host", strings.ReplaceAll(strings.ReplaceAll(host, "\n", ""), "\r", "")) // #nosec G706
	}
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		slog.Error("Failed to create Storage client", "error", err)
		os.Exit(1)
	}
	slog.Info("Storage client initialized successfully")

	// Parse templates
	templateFuncs := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}
	templates, err := template.New("").Funcs(templateFuncs).ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		slog.Error("Error parsing templates", "error", err)
		os.Exit(1)
	}

	// Initialize our store
	dataStore := store.NewStore(firestoreClient, storageClient, bucketName)

	// Initialize services
	swarmService := service.NewSwarmService(dataStore)

	// Initialize handlers with dependencies
	h := &handlers.Handlers{
		Store:             dataStore,
		SwarmService:      swarmService,
		LocationService:   &handlers.NominatimLocationService{Client: &http.Client{Timeout: 10 * time.Second}},
		GoogleOAuthConfig: googleOAuthConfig,
		Version:           version,
		Templates:         templates,
		FrontendAssetsURL: getEnv("FRONTEND_ASSETS_URL", ""), // Default to empty string for local dev
	}

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("GET /{$}", h.IndexHandler)
	mux.HandleFunc("GET /get_swarms", h.GetSwarmsHandler)
	mux.HandleFunc("GET /login", h.LoginPageHandler)
	mux.HandleFunc("GET /register", h.RegisterPageHandler)
	mux.HandleFunc("GET /auth/google", h.GoogleLoginHandler)
	mux.HandleFunc("GET /auth/google/callback", h.GoogleCallbackHandler)
	mux.HandleFunc("GET /auth/apple", h.AppleLoginHandler)
	mux.HandleFunc("GET /auth/apple/callback", h.AppleCallbackHandler)
	mux.HandleFunc("POST /auth/login", h.UsernameLoginHandler)
	mux.HandleFunc("POST /auth/register", h.UsernameRegisterHandler)
	mux.HandleFunc("GET /auth/verify-email", h.VerifyEmailHandler)
	mux.HandleFunc("GET /auth/forgot-password", h.ForgotPasswordHandler)
	mux.HandleFunc("POST /auth/forgot-password", h.ForgotPasswordHandler)
	mux.HandleFunc("GET /auth/reset-password", h.ResetPasswordHandler)
	mux.HandleFunc("POST /auth/reset-password", h.ResetPasswordHandler)
	mux.HandleFunc("GET /logout", h.LogoutHandler)
	mux.HandleFunc("GET /auth", h.AuthHandler)
	mux.HandleFunc("POST /prepare_swarm", h.PrepareSwarmHandler)
	mux.HandleFunc("POST /confirm_swarm", h.ConfirmSwarmHandler)
	mux.HandleFunc("POST /demo/generate_sample_data", h.GenerateSampleDataHandler)
	mux.HandleFunc("POST /api/track_visit", h.TrackVisitHandler)
	mux.HandleFunc("GET /api/visits", h.VisitsAPIHandler)
	mux.HandleFunc("GET /bootstrap", h.BootstrapHandler)
	mux.HandleFunc("POST /bootstrap", h.BootstrapHandler)

	// Authenticated routes
	mux.Handle("GET /dashboard", h.RequireAuth(http.HandlerFunc(h.DashboardHandler)))
	mux.Handle("GET /swarmlist", h.RequireAuth(http.HandlerFunc(h.SwarmListHandler)))
	mux.Handle("GET /collectorsmap", h.RequireAuth(http.HandlerFunc(h.CollectorsMapHandler)))
	mux.Handle("GET /admin", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.AdminHandler))))
	mux.Handle("POST /admin/approve_user", h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.ApproveUserHandler))))
	mux.Handle("POST /admin/reject_user", h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.RejectUserHandler))))
	mux.Handle("POST /admin/delete_swarm", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.DeleteSwarmHandler))))
	mux.Handle("POST /admin/promote_user", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.PromoteUserHandler))))
	mux.Handle("GET /collector_admin", h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.CollectorAdminHandler))))
	mux.Handle("POST /update_swarm_status", h.RequireAuth(h.RequireRole("collector", http.HandlerFunc(h.UpdateSwarmStatusHandler))))
	mux.Handle("POST /assign_swarm", h.RequireAuth(h.RequireRole("collector", http.HandlerFunc(h.AssignSwarmHandler))))
	mux.Handle("POST /claim_swarm", h.RequireAuth(h.RequireRole("collector", http.HandlerFunc(h.ClaimSwarmHandler))))
	// Add other routes here as they are refactored

	port := getEnv("PORT", "8080")
	// Validate port to prevent log injection and ensure it's a valid port number
	if _, err := strconv.Atoi(port); err != nil {
		slog.Error("Invalid PORT", "port", strings.ReplaceAll(strings.ReplaceAll(port, "\n", ""), "\r", ""), "error", err) // #nosec G706
		os.Exit(1)
	}
	slog.Info("Starting server", "port", strings.ReplaceAll(strings.ReplaceAll(port, "\n", ""), "\r", ""), "version", strings.ReplaceAll(strings.ReplaceAll(version, "\n", ""), "\r", "")) // #nosec G706

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
