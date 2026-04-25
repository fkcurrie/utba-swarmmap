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
	"cloud.google.com/go/vertexai/genai"
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

	// Initialize LocationService
	var locationService handlers.LocationService
	mapboxToken := strings.TrimSpace(os.Getenv("MAPBOX_ACCESS_TOKEN"))
	if mapboxToken != "" {
		locationService = &handlers.MapboxLocationService{
			Client:      &http.Client{Timeout: 10 * time.Second},
			AccessToken: mapboxToken,
		}
		slog.Info("Using Mapbox Location Service")
	} else {
		locationService = &handlers.NominatimLocationService{
			Client: &http.Client{Timeout: 10 * time.Second},
		}
		slog.Info("Using Nominatim Location Service")
	}

	frontendAssetsURL := strings.TrimSpace(getEnv("FRONTEND_ASSETS_URL", ""))
	frontendAssetsURL = strings.TrimSuffix(frontendAssetsURL, "/")

	githubToken := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	githubRepo := strings.TrimSpace(os.Getenv("GITHUB_REPO"))
	if githubRepo == "" {
		githubRepo = "fkcurrie/utba-swarmmap"
	}

	if githubToken == "" {
		slog.Warn("GITHUB_TOKEN is not set; feedback submission will be disabled")
	} else {
		slog.Info("GitHub integration configured", "repo", githubRepo)
	}

	// Initialize AI Service
	var aiService handlers.AIService
	geminiModel := getEnv("GEMINI_MODEL", "gemini-1.5-flash") // Default to a known stable model
	gcpLocation := getEnv("GCP_LOCATION", "us-central1")

	aiClient, err := genai.NewClient(ctx, projectID, gcpLocation)
	if err != nil {
		slog.Warn("Failed to initialize Vertex AI client, AI interpretation will be disabled", "error", err)
	} else {
		defer aiClient.Close()
		aiService = &handlers.VertexAIService{
			Client: aiClient,
			Model:  geminiModel,
		}
		slog.Info("Vertex AI Gemini service initialized", "model", geminiModel, "location", gcpLocation)
	}

	// Initialize handlers with dependencies
	h := &handlers.Handlers{
		Store:             dataStore,
		SwarmService:      swarmService,
		LocationService:   locationService,
		GitHubService:     &handlers.RealGitHubService{Client: &http.Client{Timeout: 10 * time.Second}},
		AIService:         aiService,
		GoogleOAuthConfig: googleOAuthConfig,
		Version:           version,
		Templates:         templates,
		FrontendAssetsURL: frontendAssetsURL,
		MapboxToken:       mapboxToken,
		GithubToken:       githubToken,
		GithubRepo:        githubRepo,
	}

	mux := http.NewServeMux()

	// Static file handler
	// This consolidated handler serves static assets from ./static (for production/Docker)
	// or ../frontend/static (for local development), ensuring backend self-sufficiency.
	staticDir := "./static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		staticDir = "../frontend/static"
	}

	if _, err := os.Stat(staticDir); err == nil {
		slog.Info("Serving static files", "dir", staticDir)
		fs := http.FileServer(http.Dir(staticDir))
		// Use the GET prefix to avoid conflict with the catch-all root handler in Go 1.22+
		mux.Handle("GET /static/", http.StripPrefix("/static/", fs))
	} else {
		slog.Warn("Static files directory not found, some assets may fail to load", "dir", staticDir)
	}

	// Health and utility routes
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Public routes
	// Root handler matches "/" and acts as a catch-all for unknown GET requests.
	// IndexHandler contains logic to return 404 for unknown sub-paths.
	mux.HandleFunc("GET /", h.IndexHandler)
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
	mux.HandleFunc("POST /demo/generate_sample_data", h.RequireAuth(h.RequireRole("site_admin", h.VerifyCSRF(http.HandlerFunc(h.GenerateSampleDataHandler)))).ServeHTTP)
	mux.HandleFunc("POST /api/track_visit", h.TrackVisitHandler)
	mux.Handle("POST /api/feedback", h.WithSession(h.VerifyCSRF(http.HandlerFunc(h.FeedbackHandler))))
	mux.Handle("GET /api/visits", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.VisitsAPIHandler))))
	mux.HandleFunc("GET /bootstrap", h.BootstrapHandler)
	mux.HandleFunc("POST /bootstrap", h.BootstrapHandler)

	// Authenticated routes
	mux.Handle("GET /dashboard", h.RequireAuth(http.HandlerFunc(h.DashboardHandler)))
	mux.Handle("GET /swarmlist", h.RequireAuth(http.HandlerFunc(h.SwarmListHandler)))
	mux.Handle("GET /collectorsmap", h.RequireAuth(http.HandlerFunc(h.CollectorsMapHandler)))
	mux.Handle("GET /admin", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.AdminHandler))))
	mux.Handle("POST /admin/approve_user", h.RequireAuth(h.RequireRole("collector_admin", h.VerifyCSRF(http.HandlerFunc(h.ApproveUserHandler)))))
	mux.Handle("POST /admin/reject_user", h.RequireAuth(h.RequireRole("collector_admin", h.VerifyCSRF(http.HandlerFunc(h.RejectUserHandler)))))
	mux.Handle("POST /admin/delete_swarm", h.RequireAuth(h.RequireRole("site_admin", h.VerifyCSRF(http.HandlerFunc(h.DeleteSwarmHandler)))))
	mux.Handle("POST /admin/promote_user", h.RequireAuth(h.RequireRole("site_admin", h.VerifyCSRF(http.HandlerFunc(h.PromoteUserHandler)))))
	mux.Handle("GET /collector_admin", h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.CollectorAdminHandler))))
	mux.Handle("POST /update_swarm_status", h.RequireAuth(h.RequireRole("collector", h.VerifyCSRF(http.HandlerFunc(h.UpdateSwarmStatusHandler)))))
	mux.Handle("POST /assign_swarm", h.RequireAuth(h.RequireRole("collector", h.VerifyCSRF(http.HandlerFunc(h.AssignSwarmHandler)))))
	mux.Handle("POST /claim_swarm", h.RequireAuth(h.RequireRole("collector", h.VerifyCSRF(http.HandlerFunc(h.ClaimSwarmHandler)))))
	mux.Handle("POST /unclaim_swarm", h.RequireAuth(h.RequireRole("collector", h.VerifyCSRF(http.HandlerFunc(h.UnclaimSwarmHandler)))))
	// Add other routes here as they are refactored

	port := getEnv("PORT", "8080")
	// Validate port to prevent log injection and ensure it's a valid port number
	if _, err := strconv.Atoi(port); err != nil {
		slog.Error("Invalid PORT", "port", strings.ReplaceAll(strings.ReplaceAll(port, "\n", ""), "\r", ""), "error", err) // #nosec G706
		os.Exit(1)
	}
	slog.Info("Starting server", "port", strings.ReplaceAll(strings.ReplaceAll(port, "\n", ""), "\r", ""), "version", strings.ReplaceAll(strings.ReplaceAll(version, "\n", ""), "\r", "")) // #nosec G706

	// Apply security headers to all routes
	handler := h.SecurityHeaders(mux)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
