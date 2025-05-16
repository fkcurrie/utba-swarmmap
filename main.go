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
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

const projectID = "utba-swarmmap"
const reportsCollection = "swarms"

var (
	version           = "dev"
	firestoreClient   *firestore.Client
	storageClient     *storage.Client
	bucketName        = "utba-swarmmap-media"
	templates         *template.Template
	maxFileSize       = int64(10 << 20) // 10MB
	allowedImageTypes = map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
		"image/heic": true,
		"image/heif": true,
	}
	allowedVideoTypes = map[string]bool{
		"video/mp4":  true,
		"video/webm": true,
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
}

func init() {
	ctx := context.Background()

	// Initialize Firestore client
	var err error
	firestoreClient, err = firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create Firestore client: %v", err)
	}

	// Initialize Storage client
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create Storage client: %v", err)
	}

	// Parse templates
	templates, err = template.ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		log.Fatalf("Error parsing templates: %v", err)
	}
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
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/report_swarm", reportSwarmHandler)
	http.HandleFunc("/get_swarms", getSwarmsHandler)
	http.HandleFunc("/update_swarm_status", updateSwarmStatusHandler)
	http.HandleFunc("/swarmlist", swarmListHandler)
	http.HandleFunc("/prepare_swarm", prepareSwarmHandler)
	http.HandleFunc("/confirm_swarm", confirmSwarmHandler)

	// Serve static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	err := templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Version": version,
	})
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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

	// Create the swarm report
	now := time.Now()
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

	iter := firestoreClient.Collection(reportsCollection).Documents(ctx)
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
		if report.Status != "Captured" && time.Since(report.ReportedTimestamp).Hours() > 24*7 {
			report.DisplayStatus = "Archived"
		}
		currentReports = append(currentReports, report)
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

	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if updateReq.ID == "" || updateReq.Status == "" {
		http.Error(w, "Missing id or status in request", http.StatusBadRequest)
		return
	}

	docRef := firestoreClient.Collection(reportsCollection).Doc(updateReq.ID)
	currentTime := time.Now().UTC()
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
		// Consider checking for errcodes.NotFound specifically
		return
	}

	// Fetch the updated document to return it
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

	// Render the swarm list page using a new template
	tmpl, err := template.ParseFiles("templates/swarmlist.html")
	if err != nil {
		http.Error(w, "Failed to parse swarm list template", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, map[string]interface{}{
		"Swarms":  swarms,
		"Version": version,
	}); err != nil {
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
	if !allowedImageTypes[contentType] && !allowedVideoTypes[contentType] {
		return fmt.Errorf("file %s has unsupported type %s", file.Filename, contentType)
	}

	return nil
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

	// Validate files
	form := r.MultipartForm
	if form == nil || form.File == nil {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	mediaFilenames := []string{}
	for _, files := range form.File {
		for _, file := range files {
			if err := validateFile(file); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mediaFilenames = append(mediaFilenames, file.Filename)
		}
	}

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

	// Validate files
	form := r.MultipartForm
	if form == nil || form.File == nil {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	now := time.Now()
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
	}

	// Upload files to GCS
	for _, files := range form.File {
		for _, file := range files {
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
		}
	}

	// Save to Firestore
	_, err = firestoreClient.Collection(reportsCollection).Doc(swarmID).Set(r.Context(), report)
	if err != nil {
		http.Error(w, "Failed to save report", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
