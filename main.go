package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const projectID = "utba-swarmmap"
const reportsCollection = "swarms"
const usersCollection = "users"
const sessionsCollection = "sessions" // Add sessions collection

var (
	version           = "dev"
	firestoreClient   *firestore.Client
	storageClient     *storage.Client
	bucketName        = "utba-swarmmap-media"
	templates         *template.Template
	maxFileSize       = int64(10 << 20) // 10MB
	torontoLocation   *time.Location
	// Remove in-memory sessions - will use Firestore instead
	googleOAuthConfig *oauth2.Config
	allowedImageTypes = map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
		"image/heic": true,
		"image/heif": true,
	}
	allowedVideoTypes = map[string]bool{
		"video/mp4":        true,
		"video/webm":       true,
		"video/quicktime":  true,  // iPhone/iOS videos
		"video/x-msvideo": true,   // AVI format
		"video/avi":       true,   // AVI alternative
		"video/mov":       true,   // MOV format
		"video/3gpp":      true,   // 3GP format (some Android phones)
		"video/3gp":       true,   // 3GP alternative
	}
)

// SwarmReport defines the structure for a swarm report (matches Firestore document)
type SwarmReport struct {
	ID                    string    `firestore:"-" json:"id"` // Firestore doc ID, not stored in doc fields
	Latitude              float64   `firestore:"latitude" json:"latitude"`
	Longitude             float64   `firestore:"longitude" json:"longitude"`
	Description           string    `firestore:"description" json:"description"`
	Status                string    `firestore:"status" json:"status"`
	ReportedTimestamp     time.Time `firestore:"reportedTimestamp" json:"reportedTimestamp"`
	VerificationTimestamp time.Time `firestore:"verificationTimestamp,omitempty" json:"verificationTimestamp,omitempty"`
	CapturedTimestamp     time.Time `firestore:"capturedTimestamp,omitempty" json:"capturedTimestamp,omitempty"`
	LastUpdatedTimestamp  time.Time `firestore:"lastUpdatedTimestamp" json:"lastUpdatedTimestamp"`
	ReportedMediaURLs     []string  `firestore:"reportedMediaURLs,omitempty" json:"reportedMediaURLs,omitempty"`
	CapturedMediaURLs     []string  `firestore:"capturedMediaURLs,omitempty" json:"capturedMediaURLs,omitempty"`
	BeekeeperNotes        string    `firestore:"beekeeperNotes,omitempty" json:"beekeeperNotes,omitempty"`
	DisplayStatus         string    `firestore:"-" json:"displayStatus,omitempty"` // Transient, for frontend logic
	NearestIntersection   string    `firestore:"nearestIntersection,omitempty" json:"nearestIntersection,omitempty"`
	AssignedCollectorID   string    `firestore:"assignedCollectorID,omitempty" json:"assignedCollectorID,omitempty"`
	// Contact information for public reporters
	ReporterName          string    `firestore:"reporterName,omitempty" json:"reporterName,omitempty"`
	ReporterEmail         string    `firestore:"reporterEmail,omitempty" json:"reporterEmail,omitempty"`
	ReporterPhone         string    `firestore:"reporterPhone,omitempty" json:"reporterPhone,omitempty"`
	ReporterSessionID     string    `firestore:"reporterSessionID,omitempty" json:"reporterSessionID,omitempty"` // To track public user's reports
}

// User defines the structure for swarm collectors and admins
type User struct {
	ID        string    `json:"id" firestore:"-"`
	Email     string    `json:"email" firestore:"email"`
	Phone     string    `json:"phone" firestore:"phone"`
	Name      string    `json:"name" firestore:"name"`
	Location  string    `json:"location" firestore:"location"`
	Role      string    `json:"role" firestore:"role"`         // "site_admin", "collector_admin", or "collector"
	Status    string    `json:"status" firestore:"status"`     // "pending" or "approved"
	CreatedAt time.Time `json:"created_at" firestore:"created_at"`
}

// Session defines user session structure
type Session struct {
	UserID    string    `json:"userID"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func init() {
	ctx := context.Background()

	// Initialize Toronto time location
	var err error
	torontoLocation, err = time.LoadLocation("America/Toronto")
	if err != nil {
		log.Printf("Warning: Failed to load Toronto timezone: %v. Using UTC.", err)
		torontoLocation = time.UTC
	}

	// Initialize Google OAuth2 configuration
	googleOAuthConfig = &oauth2.Config{
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
	firestoreClient, err = firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Printf("Warning: Failed to create Firestore client: %v. Some functionality may be limited.", err)
	}

	// Initialize Storage client
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Printf("Warning: Failed to create Storage client: %v. Some functionality may be limited.", err)
	}

	// Parse templates
	templateFuncs := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}
	
	templates, err = template.New("").Funcs(templateFuncs).ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		log.Printf("Warning: Error parsing templates: %v. Using default templates.", err)
		// Create a minimal fallback template to prevent nil pointer panics
		templates = template.Must(template.New("fallback").Parse(`
			<!DOCTYPE html><html><head><title>UTBA Swarm Map</title></head>
			<body><h1>UTBA Swarm Map</h1><p>Templates are loading...</p></body></html>
		`))
	}

	log.Printf("Initialization complete. Version: %s", version)
}

func generateUniqueID() string {
	return uuid.New().String()
}

func uploadToGCS(ctx context.Context, swarmID string, file io.Reader, filename string) (string, error) {
	// Create a unique filename to avoid collisions
	ext := filepath.Ext(filename)
	uniqueFilename := fmt.Sprintf("%s/%s%s", swarmID, uuid.New().String(), ext)
	log.Printf("Uploading file %s to GCS as %s", filename, uniqueFilename)

	// Create a new object in the bucket
	obj := storageClient.Bucket(bucketName).Object(uniqueFilename)
	writer := obj.NewWriter(ctx)

	// Set the content type based on file extension
	switch ext {
	case ".jpg", ".jpeg":
		writer.ContentType = "image/jpeg"
	case ".png":
		writer.ContentType = "image/png"
	case ".gif":
		writer.ContentType = "image/gif"
	case ".heic", ".heif":
		writer.ContentType = "image/heic"
	case ".mp4":
		writer.ContentType = "video/mp4"
	case ".webm":
		writer.ContentType = "video/webm"
	case ".mov", ".MOV":
		writer.ContentType = "video/quicktime"
	case ".avi", ".AVI":
		writer.ContentType = "video/x-msvideo"
	case ".3gp", ".3GP":
		writer.ContentType = "video/3gpp"
	default:
		writer.ContentType = "application/octet-stream"
	}
	log.Printf("Setting content type to %s for file %s", writer.ContentType, filename)

	// Make the object publicly readable
	writer.ACL = []storage.ACLRule{{Entity: storage.AllUsers, Role: storage.RoleReader}}

	// Copy the file data
	if _, err := io.Copy(writer, file); err != nil {
		log.Printf("Failed to copy file data for %s: %v", filename, err)
		return "", fmt.Errorf("failed to copy file data: %v", err)
	}

	// Close the writer
	if err := writer.Close(); err != nil {
		log.Printf("Failed to close writer for %s: %v", filename, err)
		return "", fmt.Errorf("failed to close writer: %v", err)
	}

	// Return the public URL
	url := fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucketName, uniqueFilename)
	log.Printf("Successfully uploaded %s to %s", filename, url)
	return url, nil
}

func main() {
	mux := http.NewServeMux()
	
	// Public routes (no authentication required)
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/report_swarm", reportSwarmHandler)
	mux.HandleFunc("/get_swarms", getSwarmsHandler)
	mux.HandleFunc("/prepare_swarm", prepareSwarmHandler)
	mux.HandleFunc("/confirm_swarm", confirmSwarmHandler)
	
	// Authentication routes
	mux.HandleFunc("/login", googleLoginHandler)
	mux.HandleFunc("/auth/google/callback", googleCallbackHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/bootstrap", bootstrapAdminHandler)
	
	// Protected routes (require authentication)
	mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
	mux.HandleFunc("/swarmlist", requireAuth(swarmListHandler))
	mux.HandleFunc("/admin", requireRole("site_admin", siteAdminHandler))
	mux.HandleFunc("/collector_admin", requireRole("collector_admin", collectorAdminHandler))
	mux.HandleFunc("/admin/approve_user", requireRole("collector_admin", approveUserHandler))
	mux.HandleFunc("/admin/reject_user", requireRole("collector_admin", rejectUserHandler))
	mux.HandleFunc("/admin/delete_swarm", requireRole("site_admin", deleteSwarmHandler))
	mux.HandleFunc("/admin/promote_user", requireRole("site_admin", promoteUserHandler))
	mux.HandleFunc("/update_swarm_status", requireRole("collector", updateSwarmStatusHandler))
	mux.HandleFunc("/assign_swarm", requireRole("collector", assignSwarmHandler))
	mux.HandleFunc("/collectorsmap", requireAuth(collectorsMapHandler))

	// Demo/Development routes
	mux.HandleFunc("/demo/generate_sample_data", generateSampleDataHandler)

	// Serve static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	log.Printf("Server version: %s", version)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	if templates == nil {
		log.Printf("Templates not loaded, serving fallback HTML")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>UTBA Swarm Map</title></head>
		<body><h1>UTBA Swarm Map - Loading...</h1><p>Service is starting up...</p></body></html>`))
		return
	}
	
	err := templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Version": version,
	})
	if err != nil {
		log.Printf("Error executing template: %v", err)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>UTBA Swarm Map</title></head>
		<body><h1>UTBA Swarm Map</h1><p>Template error - please refresh</p></body></html>`))
	}
}

func reportSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB max
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Generate a unique ID for this swarm
	swarmID := generateUniqueID()

	// Get form values
	description := r.FormValue("description")
	latitude := r.FormValue("latitude")
	longitude := r.FormValue("longitude")
	nearestIntersection := r.FormValue("intersection")
	
	// Get contact information
	reporterName := r.FormValue("reporterName")
	reporterEmail := r.FormValue("reporterEmail")
	reporterPhone := r.FormValue("reporterPhone")
	reporterSessionID := r.FormValue("reporterSessionId")
	
	log.Printf("Creating swarm report for session %s with contact: %s <%s> %s", reporterSessionID, reporterName, reporterEmail, reporterPhone)

	// Create the swarm report
	now := getCurrentTorontoTime()
	report := SwarmReport{
		ID:                   swarmID,
		Description:          description,
		Status:               "Reported",
		DisplayStatus:        "Reported",
		Latitude:             parseFloat(latitude),
		Longitude:            parseFloat(longitude),
		NearestIntersection:  nearestIntersection,
		ReportedTimestamp:    now,
		LastUpdatedTimestamp: now,
		ReportedMediaURLs:    []string{},
		ReporterName:         reporterName,
		ReporterEmail:        reporterEmail,
		ReporterPhone:        reporterPhone,
		ReporterSessionID:    reporterSessionID,
	}

	// Handle file uploads
	form := r.MultipartForm
	if form != nil && form.File != nil {
		for _, files := range form.File {
			for _, file := range files {
				// Open the uploaded file
				src, err := file.Open()
				if err != nil {
					http.Error(w, "Failed to open uploaded file", http.StatusInternalServerError)
					return
				}
				defer src.Close()

				// Upload to GCS
				mediaURL, err := uploadToGCS(r.Context(), swarmID, src, file.Filename)
				if err != nil {
					http.Error(w, fmt.Sprintf("Failed to upload file: %v", err), http.StatusInternalServerError)
					return
				}

				// Add the URL to the report
				report.ReportedMediaURLs = append(report.ReportedMediaURLs, mediaURL)
			}
		}
	}

	// Save to Firestore
	_, err := firestoreClient.Collection(reportsCollection).Doc(swarmID).Set(r.Context(), report)
	if err != nil {
		http.Error(w, "Failed to save report", http.StatusInternalServerError)
		return
	}

	// Return the created report
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func getSwarmsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := context.Background()
	var currentReports []SwarmReport

	// Check if this is a public user request with session ID
	sessionID := r.URL.Query().Get("sessionId")
	
	// Check if user is authenticated
	session := getSession(r)
	isAuthenticated := session != nil
	
	var iter *firestore.DocumentIterator
	if sessionID != "" && !isAuthenticated {
		// Public user - only show their swarms
		log.Printf("Fetching swarms for public user session: %s", sessionID)
		iter = firestoreClient.Collection(reportsCollection).Where("reporterSessionID", "==", sessionID).Documents(ctx)
	} else {
		// Authenticated user or no session - show all swarms
		if isAuthenticated {
			log.Printf("Fetching all swarms for authenticated user: %s (%s)", session.Username, session.Role)
		} else {
			log.Printf("Fetching all swarms (no authentication, no session)")
		}
		iter = firestoreClient.Collection(reportsCollection).Documents(ctx)
	}

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("Failed to iterate Firestore documents: %v", err)
			http.Error(w, "Error fetching reports", http.StatusInternalServerError)
			return
		}

		var report SwarmReport
		if err := doc.DataTo(&report); err != nil {
			log.Printf("Failed to convert Firestore document to SwarmReport: %v", err)
			// Optionally skip this report or return error
			continue
		}
		report.ID = doc.Ref.ID // Set the document ID

		// Dynamic DisplayStatus logic
		report.DisplayStatus = report.Status
		if report.Status != "Captured" && time.Since(report.ReportedTimestamp).Hours() > 24 {
			report.DisplayStatus = "Archived"
		}
		currentReports = append(currentReports, report)
	}

	if isAuthenticated {
		log.Printf("Returning %d swarms for authenticated user %s", len(currentReports), session.Username)
	} else if sessionID != "" {
		log.Printf("Returning %d swarms for public user session %s", len(currentReports), sessionID)
	} else {
		log.Printf("Returning %d swarms for unauthenticated request", len(currentReports))
	}
	
	data, err := json.Marshal(currentReports)
	if err != nil {
		log.Printf("Error marshalling reports to JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func updateSwarmStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := context.Background()

	var updateReq struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		BeekeeperNotes string `json:"beekeeperNotes"`
	}

	// Check Content-Type to determine how to parse the request
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		// Handle JSON request
		if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
			log.Printf("Error decoding JSON request: %v", err)
			http.Error(w, "Invalid JSON request body", http.StatusBadRequest)
			return
		}
	} else {
		// Handle form data request
		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form data: %v", err)
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		updateReq.ID = r.FormValue("id")
		updateReq.Status = r.FormValue("status")
		updateReq.BeekeeperNotes = r.FormValue("beekeeperNotes")
	}

	if updateReq.ID == "" || updateReq.Status == "" {
		http.Error(w, "Missing id or status in request", http.StatusBadRequest)
		return
	}

	docRef := firestoreClient.Collection(reportsCollection).Doc(updateReq.ID)
	currentTime := getCurrentTorontoTime()
	var updates []firestore.Update

	updates = append(updates, firestore.Update{Path: "status", Value: updateReq.Status})
	updates = append(updates, firestore.Update{Path: "lastUpdatedTimestamp", Value: currentTime})

	if updateReq.BeekeeperNotes != "" {
		updates = append(updates, firestore.Update{Path: "beekeeperNotes", Value: updateReq.BeekeeperNotes})
	}

	switch updateReq.Status {
	case "Verified":
		updates = append(updates, firestore.Update{Path: "verificationTimestamp", Value: currentTime})
	case "Captured":
		updates = append(updates, firestore.Update{Path: "capturedTimestamp", Value: currentTime})
		// TODO: Handle captured media uploads here or in a separate endpoint, update CapturedMediaURLs
	}

	_, err := docRef.Update(ctx, updates)
	if err != nil {
		log.Printf("Failed to update report %s in Firestore: %v", updateReq.ID, err)
		http.Error(w, "Error updating report", http.StatusInternalServerError)
		return
	}

	// Check if this is a form submission (redirect) or API call (JSON response)
	if contentType == "application/json" {
		// Fetch the updated document to return it as JSON
		dsnap, err := docRef.Get(ctx)
		if err != nil {
			log.Printf("Failed to fetch updated report %s from Firestore: %v", updateReq.ID, err)
			http.Error(w, "Error fetching updated report", http.StatusInternalServerError)
			return
		}
		var updatedReport SwarmReport
		if err := dsnap.DataTo(&updatedReport); err != nil {
			log.Printf("Failed to convert updated Firestore document: %v", err)
			http.Error(w, "Error processing updated report", http.StatusInternalServerError)
			return
		}
		updatedReport.ID = dsnap.Ref.ID

		log.Printf("Updated swarm report %s to status %s: %+v", updatedReport.ID, updatedReport.Status, updatedReport)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updatedReport)
	} else {
		// Form submission - redirect back to dashboard
		log.Printf("Updated swarm report %s to status %s via form submission", updateReq.ID, updateReq.Status)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

// Add a new handler for the swarm list page
func swarmListHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		http.Error(w, "Failed to create Firestore client", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	iter := client.Collection("swarms").Documents(ctx)
	var swarms []SwarmReport
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			http.Error(w, "Failed to retrieve swarms", http.StatusInternalServerError)
			return
		}
		var swarm SwarmReport
		if err := doc.DataTo(&swarm); err != nil {
			http.Error(w, "Failed to parse swarm data", http.StatusInternalServerError)
			return
		}
		swarm.ID = doc.Ref.ID // Set the document ID
		swarms = append(swarms, swarm)
	}

	// Render the swarm list page using the global template
	err = templates.ExecuteTemplate(w, "swarmlist.html", map[string]interface{}{
		"Swarms":  swarms,
		"Version": version,
	})
	if err != nil {
		log.Printf("Error executing swarm list template: %v", err)
		http.Error(w, "Failed to render swarm list", http.StatusInternalServerError)
		return
	}
}

func parseFloat(str string) float64 {
	f, err := strconv.ParseFloat(str, 64)
	if err != nil {
		log.Printf("Error parsing float: %v", err)
		return 0.0
	}
	return f
}

// Add validation functions
func validateCoordinates(lat, lon string) (float64, float64, error) {
	latitude, err := strconv.ParseFloat(lat, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid latitude: %v", err)
	}
	if latitude < -90 || latitude > 90 {
		return 0, 0, fmt.Errorf("latitude must be between -90 and 90")
	}

	longitude, err := strconv.ParseFloat(lon, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid longitude: %v", err)
	}
	if longitude < -180 || longitude > 180 {
		return 0, 0, fmt.Errorf("longitude must be between -180 and 180")
	}

	return latitude, longitude, nil
}

func validateFile(file *multipart.FileHeader) error {
	if file.Size > maxFileSize {
		return fmt.Errorf("file %s is too large (max size is 10MB)", file.Filename)
	}

	contentType := file.Header.Get("Content-Type")
	
	// Check by MIME type first
	if allowedImageTypes[contentType] || allowedVideoTypes[contentType] {
		return nil
	}
	
	// Fallback: check by file extension (important for mobile uploads)
	ext := strings.ToLower(filepath.Ext(file.Filename))
	allowedExtensions := map[string]bool{
		// Image extensions
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".heic": true,
		".heif": true,
		// Video extensions
		".mp4":  true,
		".webm": true,
		".mov":  true,
		".avi":  true,
		".3gp":  true,
	}
	
	if allowedExtensions[ext] {
		log.Printf("File %s accepted by extension %s (MIME type was %s)", file.Filename, ext, contentType)
		return nil
	}
	
	return fmt.Errorf("file %s has unsupported type %s (extension: %s)", file.Filename, contentType, ext)
}

// Handler for the first step: prepare swarm (generate UUID, return summary, do not save)
func prepareSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(maxFileSize); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Validate required fields
	description := r.FormValue("description")
	if description == "" {
		http.Error(w, "Description is required", http.StatusBadRequest)
		return
	}

	latitude := r.FormValue("latitude")
	longitude := r.FormValue("longitude")
	lat, lon, err := validateCoordinates(latitude, longitude)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	nearestIntersection := r.FormValue("intersection")
	if nearestIntersection == "" {
		http.Error(w, "Nearest intersection is required", http.StatusBadRequest)
		return
	}
	
	// Get contact information (optional)
	reporterName := r.FormValue("reporterName")
	reporterEmail := r.FormValue("reporterEmail")
	reporterPhone := r.FormValue("reporterPhone")
	reporterSessionID := r.FormValue("reporterSessionId")
	
	log.Printf("Preparing swarm for session %s with contact: %s <%s> %s", reporterSessionID, reporterName, reporterEmail, reporterPhone)

	// Validate files
	form := r.MultipartForm
	if form == nil || form.File == nil {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	log.Printf("Validating files for prepare swarm request")
	mediaFilenames := []string{}
	totalFilesValidated := 0
	for fieldName, files := range form.File {
		log.Printf("Validating field '%s' with %d files", fieldName, len(files))
		for i, file := range files {
			log.Printf("Validating file %d: %s (size: %d bytes, type: %s)", i+1, file.Filename, file.Size, file.Header.Get("Content-Type"))
			
			if err := validateFile(file); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mediaFilenames = append(mediaFilenames, file.Filename)
			totalFilesValidated++
		}
	}
	log.Printf("Total files validated: %d, mediaFilenames length: %d", totalFilesValidated, len(mediaFilenames))

	swarmID := generateUniqueID()

	// Return the summary and UUID (no saving yet)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"referenceID":         swarmID,
		"description":         description,
		"latitude":            lat,
		"longitude":           lon,
		"nearestIntersection": nearestIntersection,
		"mediaFilenames":      mediaFilenames,
	})
}

// Handler for the second step: confirm swarm (save to Firestore, upload media to GCS)
func confirmSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(maxFileSize); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Validate reference ID
	swarmID := r.FormValue("referenceID")
	if swarmID == "" {
		http.Error(w, "Reference ID is required", http.StatusBadRequest)
		return
	}

	// Validate required fields
	description := r.FormValue("description")
	if description == "" {
		http.Error(w, "Description is required", http.StatusBadRequest)
		return
	}

	latitude := r.FormValue("latitude")
	longitude := r.FormValue("longitude")
	lat, lon, err := validateCoordinates(latitude, longitude)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	nearestIntersection := r.FormValue("intersection")
	if nearestIntersection == "" {
		http.Error(w, "Nearest intersection is required", http.StatusBadRequest)
		return
	}

	// Get contact information (optional)
	reporterName := r.FormValue("reporterName")
	reporterEmail := r.FormValue("reporterEmail")
	reporterPhone := r.FormValue("reporterPhone")
	reporterSessionID := r.FormValue("reporterSessionId")
	
	log.Printf("Confirming swarm %s for session %s with contact: %s <%s> %s", swarmID, reporterSessionID, reporterName, reporterEmail, reporterPhone)

	// Validate files
	form := r.MultipartForm
	if form == nil || form.File == nil {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	now := getCurrentTorontoTime()
	report := SwarmReport{
		ID:                   swarmID,
		Description:          description,
		Status:               "Reported",
		DisplayStatus:        "Reported",
		Latitude:             lat,
		Longitude:            lon,
		NearestIntersection:  nearestIntersection,
		ReportedTimestamp:    now,
		LastUpdatedTimestamp: now,
		ReportedMediaURLs:    []string{},
		ReporterName:         reporterName,
		ReporterEmail:        reporterEmail,
		ReporterPhone:        reporterPhone,
		ReporterSessionID:    reporterSessionID,
	}

	// Upload files to GCS
	log.Printf("Processing file uploads for swarm %s", swarmID)
	totalFilesProcessed := 0
	for fieldName, files := range form.File {
		log.Printf("Processing field '%s' with %d files", fieldName, len(files))
		for i, file := range files {
			log.Printf("Processing file %d: %s (size: %d bytes, type: %s)", i+1, file.Filename, file.Size, file.Header.Get("Content-Type"))
			
			if err := validateFile(file); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			src, err := file.Open()
			if err != nil {
				http.Error(w, "Failed to open uploaded file", http.StatusInternalServerError)
				return
			}
			defer src.Close()

			mediaURL, err := uploadToGCS(r.Context(), swarmID, src, file.Filename)
			if err != nil {
				http.Error(w, "Failed to upload file to GCS", http.StatusInternalServerError)
				return
			}
			report.ReportedMediaURLs = append(report.ReportedMediaURLs, mediaURL)
			totalFilesProcessed++
			log.Printf("Successfully uploaded file %d: %s -> %s", i+1, file.Filename, mediaURL)
		}
	}
	log.Printf("Total files processed for swarm %s: %d, ReportedMediaURLs length: %d", swarmID, totalFilesProcessed, len(report.ReportedMediaURLs))

	// Save to Firestore
	_, err = firestoreClient.Collection(reportsCollection).Doc(swarmID).Set(r.Context(), report)
	if err != nil {
		http.Error(w, "Failed to save report", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// Helper function to get current time in Toronto
func getCurrentTorontoTime() time.Time {
	return time.Now().In(torontoLocation)
}

// Authentication handlers
func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateUniqueID()
	// Add prompt=select_account to force Google account chooser
	url := googleOAuthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	
	// Verify state parameter exists and is valid (basic check)
	if state == "" {
		http.Error(w, "Invalid state parameter", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	token, err := googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		http.Error(w, "Failed to authenticate", http.StatusInternalServerError)
		return
	}

	client := googleOAuthConfig.Client(ctx, token)
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
	iter := firestoreClient.Collection(usersCollection).Where("email", "==", userInfo.Email).Documents(ctx)
	doc, err := iter.Next()
	
	if err == iterator.Done {
		// User doesn't exist, create new user with pending status
		user := User{
			Email:     userInfo.Email,
			Name:      userInfo.Name,
			Role:      "collector",
			Status:    "pending", // Requires admin approval
			CreatedAt: getCurrentTorontoTime(),
		}
		
		userID := generateUniqueID()
		_, err = firestoreClient.Collection(usersCollection).Doc(userID).Set(ctx, user)
		if err != nil {
			log.Printf("Failed to create user: %v", err)
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
		
		// Show pending approval message
		showPendingApprovalPage(w, userInfo.Name)
		return
	}
	
	if err != nil {
		log.Printf("Failed to query user: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	
	// User exists, check their status
	var existingUser User
	if err := doc.DataTo(&existingUser); err != nil {
		log.Printf("Failed to decode user: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	existingUser.ID = doc.Ref.ID
	
	if existingUser.Status != "approved" {
		showPendingApprovalPage(w, existingUser.Name)
		return
	}
	
	// User is approved, create session and log them in
	sessionID := createSession(existingUser.ID, existingUser.Email, existingUser.Role)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   true,  // Required for HTTPS
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

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		// Delete session from Firestore
		deleteSession(cookie.Value)
		log.Printf("User logged out, deleted session from Firestore: %s", cookie.Value)
	} else if err != nil {
		log.Printf("Logout called but no session cookie found: %v", err)
	} else {
		log.Printf("Logout called but session cookie was empty.")
	}
	
	// Standard and most reliable way to clear a cookie:
	// Set its MaxAge to -1 (or Expires to a past date).
	// Ensure Path, Domain (if set during creation), Secure, and HttpOnly match the original cookie.
	// Our session cookie is set with Path="/", Secure=true, HttpOnly=true, SameSite=LaxMode.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "", // Value can be empty
		Path:     "/",
		MaxAge:   -1, // Tells the browser to delete the cookie immediately
		HttpOnly: true,
		Secure:   true, // Must match how it was set
		SameSite: http.SameSiteLaxMode, // Must match how it was set
	})

	// Add aggressive cache control headers for the logout response itself
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Clear-Site-Data", "\"cookies\", \"cache\"") // Focus on cookies and cache for logout response
	
	log.Printf("User logged out. Cookie cleared. Redirecting to home.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		log.Printf("/auth: No active session found.")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": false})
		return
	}
	
	// Log the session details, especially the role, before sending
	log.Printf("/auth: Active session found. UserID: %s, Username: %s, Role: '%s', ExpiresAt: %v", 
		session.UserID, session.Username, session.Role, session.ExpiresAt)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"user":          session,
	})
}

// Authentication middleware
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Add cache control headers to prevent browser caching of protected pages
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		
		session := getSession(r)
		if session == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Add cache control headers to prevent browser caching of protected pages
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		
		session := getSession(r)
		if session == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		// Role hierarchy: site_admin can access everything
		if session.Role == "site_admin" {
			next(w, r)
			return
		}
		
		// collector_admin can access collector management functions
		if session.Role == "collector_admin" && (role == "collector_admin" || role == "collector") {
			next(w, r)
			return
		}
		
		// Regular role check
		if session.Role == role {
			next(w, r)
			return
		}
		
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

func getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	
	ctx := context.Background()
	doc, err := firestoreClient.Collection(sessionsCollection).Doc(cookie.Value).Get(ctx)
	if err != nil {
		log.Printf("Session not found in Firestore: %s", cookie.Value)
		return nil
	}
	
	var session Session
	if err := doc.DataTo(&session); err != nil {
		log.Printf("Failed to decode session: %v", err)
		return nil
	}
	
	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		log.Printf("Session expired: %s", cookie.Value)
		deleteSession(cookie.Value)
		return nil
	}
	
	// Additional validation - ensure session ID is not empty
	if session.UserID == "" {
		log.Printf("Invalid session - empty UserID: %s", cookie.Value)
		deleteSession(cookie.Value)
		return nil
	}
	
	return &session
}

func createSession(userID, email, role string) string {
	sessionID := generateUniqueID()
	session := Session{
		UserID:    userID,
		Username:  email,
		Role:      role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	
	ctx := context.Background()
	_, err := firestoreClient.Collection(sessionsCollection).Doc(sessionID).Set(ctx, session)
	if err != nil {
		log.Printf("Failed to create session in Firestore: %v", err)
		return ""
	}
	
	log.Printf("Created session %s for user %s with role %s", sessionID, userID, role)
	return sessionID
}

func deleteSession(sessionID string) {
	ctx := context.Background()
	_, err := firestoreClient.Collection(sessionsCollection).Doc(sessionID).Delete(ctx)
	if err != nil {
		log.Printf("Failed to delete session from Firestore: %v", err)
	} else {
		log.Printf("Deleted session from Firestore: %s", sessionID)
	}
}

// Dashboard handlers
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	ctx := context.Background()
	
	// Get available swarms for assignment
	var availableSwarms []SwarmReport
	iter := firestoreClient.Collection(reportsCollection).Where("status", "==", "Reported").Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("Failed to iterate swarms: %v", err)
			continue
		}
		
		var swarm SwarmReport
		if err := doc.DataTo(&swarm); err != nil {
			continue
		}
		swarm.ID = doc.Ref.ID
		
		// Only show swarms not assigned to anyone or assigned to current user
		if swarm.AssignedCollectorID == "" || swarm.AssignedCollectorID == session.UserID {
			availableSwarms = append(availableSwarms, swarm)
		}
	}
	
	// Get user's assigned swarms
	var assignedSwarms []SwarmReport
	iter2 := firestoreClient.Collection(reportsCollection).Where("assignedCollectorID", "==", session.UserID).Documents(ctx)
	for {
		doc, err := iter2.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			continue
		}
		
		var swarm SwarmReport
		if err := doc.DataTo(&swarm); err != nil {
			continue
		}
		swarm.ID = doc.Ref.ID
		assignedSwarms = append(assignedSwarms, swarm)
	}
	
	// Determine navigation options based on role
	showCollectorAdmin := session.Role == "collector_admin" || session.Role == "site_admin"
	showSiteAdmin := session.Role == "site_admin"
	
	err := templates.ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Version":            version,
		"User":              session,
		"AvailableSwarms":   availableSwarms,
		"AssignedSwarms":    assignedSwarms,
		"ShowCollectorAdmin": showCollectorAdmin,
		"ShowSiteAdmin":      showSiteAdmin,
	})
	if err != nil {
		log.Printf("Error executing dashboard template: %v", err)
		http.Error(w, "Failed to parse dashboard template", http.StatusInternalServerError)
		return
	}
}

func siteAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	
	// Get pending users
	var pendingUsers []User
	iter := firestoreClient.Collection(usersCollection).Where("status", "==", "pending").Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			continue
		}
		
		var user User
		if err := doc.DataTo(&user); err != nil {
			continue
		}
		user.ID = doc.Ref.ID
		pendingUsers = append(pendingUsers, user)
	}
	
	// Get all users for role management
	var allUsers []User
	iter3 := firestoreClient.Collection(usersCollection).Documents(ctx)
	for {
		doc, err := iter3.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			continue
		}
		
		var user User
		if err := doc.DataTo(&user); err != nil {
			continue
		}
		user.ID = doc.Ref.ID
		allUsers = append(allUsers, user)
	}
	
	// Get all swarms
	var allSwarms []SwarmReport
	iter2 := firestoreClient.Collection(reportsCollection).Documents(ctx)
	for {
		doc, err := iter2.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			continue
		}
		
		var swarm SwarmReport
		if err := doc.DataTo(&swarm); err != nil {
			continue
		}
		swarm.ID = doc.Ref.ID
		allSwarms = append(allSwarms, swarm)
	}
	
	err := templates.ExecuteTemplate(w, "admin.html", map[string]interface{}{
		"Version":      version,
		"PendingUsers": pendingUsers,
		"AllUsers":     allUsers,
		"AllSwarms":    allSwarms,
	})
	if err != nil {
		log.Printf("Error executing admin template: %v", err)
		http.Error(w, "Failed to parse admin template", http.StatusInternalServerError)
		return
	}
}

func collectorAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	
	// Get pending users
	var pendingUsers []User
	iter := firestoreClient.Collection(usersCollection).Where("status", "==", "pending").Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			continue
		}
		
		var user User
		if err := doc.DataTo(&user); err != nil {
			continue
		}
		user.ID = doc.Ref.ID
		pendingUsers = append(pendingUsers, user)
	}
	
	// Get all collectors (approved users with role 'collector' or 'collector_admin')
	var allCollectors []User
	iter2 := firestoreClient.Collection(usersCollection).
		Where("status", "==", "approved").
		Where("role", "in", []string{"collector", "collector_admin"}).
		Documents(ctx)
	for {
		doc, err := iter2.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("CollectorAdmin: Error fetching collectors: %v", err) // Added log
			continue
		}
		
		var user User
		if err := doc.DataTo(&user); err != nil {
			log.Printf("CollectorAdmin: Error converting user data: %v", err) // Added log
			continue
		}
		user.ID = doc.Ref.ID
		allCollectors = append(allCollectors, user)
	}
	log.Printf("CollectorAdmin: Found %d active collectors/collector_admins", len(allCollectors)) // Added log

	err := templates.ExecuteTemplate(w, "collector_admin.html", map[string]interface{}{
		"Version":         version,
		"PendingUsers":    pendingUsers,
		"AllCollectors":   allCollectors,
	})
	if err != nil {
		log.Printf("Error executing collector admin template: %v", err)
		http.Error(w, "Failed to parse collector admin template", http.StatusInternalServerError)
		return
	}
}

func assignSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	session := getSession(r)
	swarmID := r.FormValue("swarmID")
	action := r.FormValue("action")
	
	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}
	
	ctx := context.Background()
	docRef := firestoreClient.Collection(reportsCollection).Doc(swarmID)
	
	if action == "assign" {
		_, err := docRef.Update(ctx, []firestore.Update{
			{Path: "assignedCollectorID", Value: session.UserID},
			{Path: "lastUpdatedTimestamp", Value: getCurrentTorontoTime()},
		})
		if err != nil {
			http.Error(w, "Failed to assign swarm", http.StatusInternalServerError)
			return
		}
	} else if action == "unassign" {
		_, err := docRef.Update(ctx, []firestore.Update{
			{Path: "assignedCollectorID", Value: ""},
			{Path: "lastUpdatedTimestamp", Value: getCurrentTorontoTime()},
		})
		if err != nil {
			http.Error(w, "Failed to unassign swarm", http.StatusInternalServerError)
			return
		}
	}
	
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Admin handlers
func approveUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	userID := r.FormValue("userID")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}
	
	ctx := context.Background()
	_, err := firestoreClient.Collection(usersCollection).Doc(userID).Update(ctx, []firestore.Update{
		{Path: "status", Value: "approved"},
	})
	if err != nil {
		log.Printf("Failed to approve user %s: %v", userID, err)
		http.Error(w, "Failed to approve user", http.StatusInternalServerError)
		return
	}
	
	// Redirect based on user role
	session := getSession(r)
	if session != nil && session.Role == "site_admin" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/collector_admin", http.StatusSeeOther)
	}
}

func rejectUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	userID := r.FormValue("userID")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}
	
	ctx := context.Background()
	_, err := firestoreClient.Collection(usersCollection).Doc(userID).Delete(ctx)
	if err != nil {
		log.Printf("Failed to reject user %s: %v", userID, err)
		http.Error(w, "Failed to reject user", http.StatusInternalServerError)
		return
	}
	
	// Redirect based on user role
	session := getSession(r)
	if session != nil && session.Role == "site_admin" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/collector_admin", http.StatusSeeOther)
	}
}

func deleteSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	swarmID := r.FormValue("swarmID")
	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}
	
	ctx := context.Background()
	_, err := firestoreClient.Collection(reportsCollection).Doc(swarmID).Delete(ctx)
	if err != nil {
		log.Printf("Failed to delete swarm %s: %v", swarmID, err)
		http.Error(w, "Failed to delete swarm", http.StatusInternalServerError)
		return
	}
	
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func promoteUserHandler(w http.ResponseWriter, r *http.Request) {
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
	
	// Validate role
	validRoles := map[string]bool{
		"collector":       true,
		"collector_admin": true,
		"site_admin":      true,
	}
	
	if !validRoles[newRole] {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}
	
	ctx := context.Background()
	_, err := firestoreClient.Collection(usersCollection).Doc(userID).Update(ctx, []firestore.Update{
		{Path: "role", Value: newRole},
	})
	if err != nil {
		log.Printf("Failed to promote user %s to %s: %v", userID, newRole, err)
		http.Error(w, "Failed to promote user", http.StatusInternalServerError)
		return
	}
	
	log.Printf("Promoted user %s to %s role", userID, newRole)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func bootstrapAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	
	// Check if site admin users already exist
	iter := firestoreClient.Collection(usersCollection).Where("role", "==", "site_admin").Documents(ctx)
	_, err := iter.Next()
	if err != iterator.Done {
		// Site admin user already exists
		w.Header().Set("Content-Type", "text/html")
		html := `<!DOCTYPE html>
<html><head><title>Bootstrap Admin - UTBA Swarm Map</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"></head>
<body><div class="container mt-5"><div class="row justify-content-center"><div class="col-md-6">
<div class="card"><div class="card-header"><h4>Admin Bootstrap</h4></div>
<div class="card-body"><div class="alert alert-warning">
<p>Site Admin user already exists. Bootstrap is not needed.</p>
</div>
<a href="/" class="btn btn-primary">Return to Map</a>
<a href="/login" class="btn btn-secondary ml-2">Login</a></div></div></div></div></div></body></html>`
		w.Write([]byte(html))
		return
	}
	
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		html := `<!DOCTYPE html>
<html><head><title>Bootstrap Admin - UTBA Swarm Map</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"></head>
<body><div class="container mt-5"><div class="row justify-content-center"><div class="col-md-6">
<div class="card"><div class="card-header"><h4>Create Site Administrator</h4></div>
<div class="card-body">
<form method="POST">
<div class="form-group">
<label for="email">Email</label>
<input type="email" class="form-control" id="email" name="email" required>
</div>
<div class="form-group">
<label for="name">Full Name</label>
<input type="text" class="form-control" id="name" name="name" required>
</div>
<button type="submit" class="btn btn-primary">Create Site Administrator</button>
</form></div></div></div></div></div></body></html>`
		w.Write([]byte(html))
		return
	}
	
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		name := r.FormValue("name")
		
		if email == "" || name == "" {
			http.Error(w, "Email and name are required", http.StatusBadRequest)
			return
		}
		
		// Create site admin user
		user := User{
			Email:     email,
			Name:      name,
			Role:      "site_admin",
			Status:    "approved",
			CreatedAt: getCurrentTorontoTime(),
		}
		
		userID := generateUniqueID()
		_, err = firestoreClient.Collection(usersCollection).Doc(userID).Set(ctx, user)
		if err != nil {
			log.Printf("Failed to create site admin user: %v", err)
			http.Error(w, "Failed to create site admin user", http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "text/html")
		html := `<!DOCTYPE html>
<html><head><title>Bootstrap Complete - UTBA Swarm Map</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"></head>
<body><div class="container mt-5"><div class="row justify-content-center"><div class="col-md-6">
<div class="card"><div class="card-header"><h4>Site Administrator Created</h4></div>
<div class="card-body"><div class="alert alert-success">
<p>Site Administrator created successfully!</p>
<p><strong>Email:</strong> ` + email + `</p>
<p><strong>Name:</strong> ` + name + `</p>
<p><strong>Role:</strong> Site Administrator</p>
<p>You can now sign in with Google using this email address.</p>
</div>
<a href="/login" class="btn btn-primary">Login as Site Admin</a></div></div></div></div></div></body></html>`
		w.Write([]byte(html))
		return
	}
}

func generateSampleDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Parse JSON request to get session ID
	var requestData map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		// Try to get session ID from query parameter as fallback
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			http.Error(w, "Session ID required", http.StatusBadRequest)
			return
		}
		requestData = map[string]interface{}{"sessionId": sessionID}
	}
	
	sessionID, ok := requestData["sessionId"].(string)
	if !ok || sessionID == "" {
		http.Error(w, "Session ID required in request", http.StatusBadRequest)
		return
	}
	
	log.Printf("Generating sample swarms for session: %s", sessionID)
	
	ctx := context.Background()
	now := getCurrentTorontoTime()
	
	// Sample locations around Toronto for demo data
	sampleSwarms := []SwarmReport{
		{
			ID:                   generateUniqueID(),
			Description:          "Large swarm on oak tree branch, approximately 3 feet from ground. Very active, estimated 20,000+ bees.",
			Status:               "Reported",
			DisplayStatus:        "Reported",
			Latitude:             43.6532,
			Longitude:            -79.3832,
			NearestIntersection:  "Yonge & Bloor",
			ReportedTimestamp:    now.Add(-2 * time.Hour),
			LastUpdatedTimestamp: now.Add(-2 * time.Hour),
			ReportedMediaURLs:    []string{},
			ReporterName:         "Demo User",
			ReporterSessionID:    sessionID,
		},
		{
			ID:                    generateUniqueID(),
			Description:           "Medium-sized swarm on fence post in backyard. Bees appear calm, clustered in ball shape.",
			Status:                "Verified",
			DisplayStatus:         "Verified",
			Latitude:              43.6629,
			Longitude:             -79.3957,
			NearestIntersection:   "Bathurst & Dupont",
			ReportedTimestamp:     now.Add(-6 * time.Hour),
			VerificationTimestamp: now.Add(-3 * time.Hour),
			LastUpdatedTimestamp:  now.Add(-3 * time.Hour),
			BeekeeperNotes:        "Confirmed healthy swarm. Collector assigned for pickup.",
			ReportedMediaURLs:     []string{},
			ReporterName:          "Demo User",
			ReporterSessionID:     sessionID,
		},
		{
			ID:                   generateUniqueID(),
			Description:          "Small swarm under porch eaves. Homeowner wants immediate removal due to allergies.",
			Status:               "Captured",
			DisplayStatus:        "Captured",
			Latitude:             43.6426,
			Longitude:            -79.3871,
			NearestIntersection:  "Queen & University",
			ReportedTimestamp:    now.Add(-12 * time.Hour),
			VerificationTimestamp: now.Add(-8 * time.Hour),
			CapturedTimestamp:    now.Add(-2 * time.Hour),
			LastUpdatedTimestamp: now.Add(-2 * time.Hour),
			BeekeeperNotes:       "Successfully captured and relocated to apiary. Healthy queen present.",
			ReportedMediaURLs:    []string{},
			ReporterName:         "Demo User",
			ReporterSessionID:    sessionID,
		},
		{
			ID:                   generateUniqueID(),
			Description:          "Large swarm reported on maple tree in park. Very high up, estimated 15 feet.",
			Status:               "Reported",
			DisplayStatus:        "Archived",
			Latitude:             43.6677,
			Longitude:            -79.4103,
			NearestIntersection:  "Ossington & College",
			ReportedTimestamp:    now.Add(-36 * time.Hour), // Over 24 hours ago
			LastUpdatedTimestamp: now.Add(-36 * time.Hour),
			ReportedMediaURLs:    []string{},
			ReporterName:         "Demo User",
			ReporterSessionID:    sessionID,
		},
		{
			ID:                   generateUniqueID(),
			Description:          "Swarm in garden shed corner. Bees building comb, appears to be establishing hive.",
			Status:               "Verified",
			DisplayStatus:        "Verified",
			Latitude:             43.6765,
			Longitude:            -79.4167,
			NearestIntersection:  "Dundas & Lansdowne",
			ReportedTimestamp:    now.Add(-4 * time.Hour),
			VerificationTimestamp: now.Add(-1 * time.Hour),
			LastUpdatedTimestamp: now.Add(-1 * time.Hour),
			BeekeeperNotes:       "Urgent - swarm starting to build comb. Needs immediate collection.",
			ReportedMediaURLs:    []string{},
			ReporterName:         "Demo User",
			ReporterSessionID:    sessionID,
		},
		{
			ID:                   generateUniqueID(),
			Description:          "Massive swarm on birch tree in front yard. Neighbors concerned about children.",
			Status:               "Captured",
			DisplayStatus:        "Captured",
			Latitude:             43.6890,
			Longitude:            -79.3444,
			NearestIntersection:  "Danforth & Broadview",
			ReportedTimestamp:    now.Add(-8 * time.Hour),
			VerificationTimestamp: now.Add(-6 * time.Hour),
			CapturedTimestamp:    now.Add(-1 * time.Hour),
			LastUpdatedTimestamp: now.Add(-1 * time.Hour),
			BeekeeperNotes:       "Large, healthy swarm successfully captured. Queen located and secured.",
			ReportedMediaURLs:    []string{},
			ReporterName:         "Demo User",
			ReporterSessionID:    sessionID,
		},
		{
			ID:                   generateUniqueID(),
			Description:          "Small cluster of bees on apartment balcony railing. Not sure if swarm or just resting.",
			Status:               "Reported",
			DisplayStatus:        "Archived",
			Latitude:             43.6448,
			Longitude:            -79.4011,
			NearestIntersection:  "King & Spadina",
			ReportedTimestamp:    now.Add(-48 * time.Hour), // Over 24 hours ago
			LastUpdatedTimestamp: now.Add(-48 * time.Hour),
			ReportedMediaURLs:    []string{},
			ReporterName:         "Demo User",
			ReporterSessionID:    sessionID,
		},
	}
	
	// Save all sample swarms to Firestore
	var createdSwarms []SwarmReport
	var errors []string
	
	for _, swarm := range sampleSwarms {
		_, err := firestoreClient.Collection(reportsCollection).Doc(swarm.ID).Set(ctx, swarm)
		if err != nil {
			log.Printf("Failed to create sample swarm %s: %v", swarm.ID, err)
			errors = append(errors, fmt.Sprintf("Failed to create swarm at %s: %v", swarm.NearestIntersection, err))
		} else {
			createdSwarms = append(createdSwarms, swarm)
			log.Printf("Created sample swarm %s at %s with status %s for session %s", swarm.ID, swarm.NearestIntersection, swarm.Status, sessionID)
		}
	}
	
	// Return response
	response := map[string]interface{}{
		"success":        true,
		"created_count":  len(createdSwarms),
		"total_attempts": len(sampleSwarms),
		"errors":         errors,
		"sample_swarms":  createdSwarms,
		"message":        fmt.Sprintf("Generated %d sample swarms showing different statuses (Reported, Verified, Captured, Archived) for your session", len(createdSwarms)),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func collectorsMapHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(r) // We need this to potentially pass user info to the template for nav links
	if session == nil { // Should be caught by requireAuth, but good practice
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Pass session data to the template for conditional rendering of admin links in nav
	data := map[string]interface{}{
		"Version":         version,
		"UserSessionData": session, // Pass the whole session object
	}

	err := templates.ExecuteTemplate(w, "collectors_map.html", data)
	if err != nil {
		log.Printf("Error executing collectors_map.html template: %v", err)
		http.Error(w, "Failed to render collector map", http.StatusInternalServerError)
	}
}
