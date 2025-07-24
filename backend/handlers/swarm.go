package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/google/uuid"
)

var maxFileSize = int64(10 << 20) // 10MB

var (
	allowedImageTypes = map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
		"image/heic": true,
		"image/heif": true,
	}
	allowedVideoTypes = map[string]bool{
		"video/mp4":       true,
		"video/webm":      true,
		"video/quicktime": true,
		"video/x-msvideo": true,
		"video/avi":       true,
		"video/mov":       true,
		"video/3gpp":      true,
		"video/3gp":       true,
	}
)

func (h *Handlers) PrepareSwarmHandler(w http.ResponseWriter, r *http.Request) {
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

	swarmID := uuid.New().String()

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

func (h *Handlers) ConfirmSwarmHandler(w http.ResponseWriter, r *http.Request) {
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

	now := time.Now()
	report := models.SwarmReport{
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

	// In a real implementation, we would handle file uploads here.
	// For now, we'll just save the report.

	if err := h.Store.CreateSwarm(r.Context(), report); err != nil {
		http.Error(w, "Failed to save report", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

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


func (h *Handlers) UpdateSwarmStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var updateReq struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		BeekeeperNotes string `json:"beekeeperNotes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		http.Error(w, "Invalid JSON request body", http.StatusBadRequest)
		return
	}

	if updateReq.ID == "" || updateReq.Status == "" {
		http.Error(w, "Missing id or status in request", http.StatusBadRequest)
		return
	}

	currentTime := time.Now()
	var updates []firestore.Update
	updates = append(updates, firestore.Update{Path: "status", Value: updateReq.Status})
	updates = append(updates, firestore.Update{Path: "lastUpdatedTimestamp", Value: currentTime})

	if err := h.Store.UpdateSwarm(r.Context(), updateReq.ID, updates); err != nil {
		log.Printf("Failed to update report %s in Firestore: %v", updateReq.ID, err)
		http.Error(w, "Error updating report", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) AssignSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		http.Error(w, "Could not retrieve session from context", http.StatusInternalServerError)
		return
	}

	swarmID := r.FormValue("swarmID")
	action := r.FormValue("action")

	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}

	var updates []firestore.Update
	if action == "assign" {
		updates = append(updates, firestore.Update{Path: "assignedCollectorID", Value: session.UserID})
	} else if action == "unassign" {
		updates = append(updates, firestore.Update{Path: "assignedCollectorID", Value: ""})
	}
	updates = append(updates, firestore.Update{Path: "lastUpdatedTimestamp", Value: time.Now()})

	if err := h.Store.UpdateSwarm(r.Context(), swarmID, updates); err != nil {
		http.Error(w, "Failed to update swarm", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func validateFile(file *multipart.FileHeader) error {
	if file.Size > maxFileSize {
		return fmt.Errorf("file %s is too large (max size is 10MB)", file.Filename)
	}

	contentType := file.Header.Get("Content-Type")

	if allowedImageTypes[contentType] || allowedVideoTypes[contentType] {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	allowedExtensions := map[string]bool{
		".jpg":  true, ".jpeg": true, ".png": true, ".gif": true, ".heic": true, ".heif": true,
		".mp4":  true, ".webm": true, ".mov": true, ".avi": true, ".3gp": true,
	}

	if allowedExtensions[ext] {
		log.Printf("File %s accepted by extension %s (MIME type was %s)", file.Filename, ext, contentType)
		return nil
	}

	return fmt.Errorf("file %s has unsupported type %s (extension: %s)", file.Filename, contentType, ext)
}
