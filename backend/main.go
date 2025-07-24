	package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	"github.com/fkcurrie/utba-swarmmap/handlers"
	"github.com/fkcurrie/utba-swarmmap/store"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var version = "dev"

// getEnv reads an environment variable with a fallback value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
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
	firestoreClient, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create Firestore client: %v", err)
	}

	// Initialize Storage client
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create Storage client: %v", err)
	}

	// Parse templates
	templateFuncs := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}
	templates, err := template.New("").Funcs(templateFuncs).ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		log.Fatalf("Error parsing templates: %v", err)
	}

	// Initialize our store
	dataStore := store.NewStore(firestoreClient, storageClient, bucketName)

	// Initialize handlers with dependencies
	h := &handlers.Handlers{
		Store:             dataStore,
		GoogleOAuthConfig: googleOAuthConfig,
		Version:           version,
		Templates:         templates,
		FrontendAssetsURL: getEnv("FRONTEND_ASSETS_URL", ""), // Default to empty string for local dev
	}

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", h.IndexHandler)
	mux.HandleFunc("/get_swarms", h.GetSwarmsHandler)
	mux.HandleFunc("/login", h.GoogleLoginHandler)
	mux.HandleFunc("/auth/google/callback", h.GoogleCallbackHandler)
	mux.HandleFunc("/logout", h.LogoutHandler)
	mux.HandleFunc("/auth", h.AuthHandler)
	mux.HandleFunc("/prepare_swarm", h.PrepareSwarmHandler)
	mux.HandleFunc("/confirm_swarm", h.ConfirmSwarmHandler)
	mux.HandleFunc("/demo/generate_sample_data", h.GenerateSampleDataHandler)
	mux.HandleFunc("/api/track_visit", h.TrackVisitHandler)
	mux.HandleFunc("/api/visits", h.VisitsAPIHandler)

	// Authenticated routes
	mux.Handle("/dashboard", h.RequireAuth(http.HandlerFunc(h.DashboardHandler)))
	mux.Handle("/swarmlist", h.RequireAuth(http.HandlerFunc(h.SwarmListHandler)))
	mux.Handle("/collectorsmap", h.RequireAuth(http.HandlerFunc(h.CollectorsMapHandler)))
	mux.Handle("/admin", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.AdminHandler))))
	mux.Handle("/admin/approve_user", h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.ApproveUserHandler))))
	mux.Handle("/admin/reject_user", h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.RejectUserHandler))))
	mux.Handle("/admin/delete_swarm", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.DeleteSwarmHandler))))
	mux.Handle("/admin/promote_user", h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.PromoteUserHandler))))
	mux.Handle("/collector_admin", h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.CollectorAdminHandler))))
	mux.Handle("/update_swarm_status", h.RequireAuth(h.RequireRole("collector", http.HandlerFunc(h.UpdateSwarmStatusHandler))))
	mux.Handle("/assign_swarm", h.RequireAuth(h.RequireRole("collector", http.HandlerFunc(h.AssignSwarmHandler))))
	// Add other routes here as they are refactored

	port := getEnv("PORT", "8080")
	log.Printf("Starting server on port %s", port)
	log.Printf("Server version: %s", version)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
