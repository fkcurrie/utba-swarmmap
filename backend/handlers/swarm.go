// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

const maxFileSize = int64(50 << 20) // 50MB

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
		"video/mpeg":      true,
		"video/ogg":       true,
		"video/mp2t":      true, // .ts files
		"video/hevc":      true,
	}
)

func (h *Handlers) PrepareSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)
	if err := r.ParseMultipartForm(maxFileSize); err != nil && err != http.ErrNotMultipart { // #nosec G120
		slog.Error("Failed to parse multipart form", "error", err)
		h.jsonError(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Validate required fields
	description := r.FormValue("description")
	if description == "" {
		h.jsonError(w, "Description is required", http.StatusBadRequest)
		return
	}

	latitude := r.FormValue("latitude")
	longitude := r.FormValue("longitude")
	lat, lon, err := validateCoordinates(latitude, longitude)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	nearestIntersection := r.FormValue("intersection")
	if nearestIntersection == "" {
		h.jsonError(w, "Nearest intersection is required", http.StatusBadRequest)
		return
	}

	// Validate files
	form := r.MultipartForm
	if form == nil || form.File == nil {
		h.jsonError(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	mediaFilenames := []string{}
	for _, files := range form.File {
		for _, file := range files {
			if err := h.validateFile(file); err != nil {
				h.jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
			mediaFilenames = append(mediaFilenames, file.Filename)
		}
	}

	swarmID := uuid.New().String()

	mediaURLs := []string{}
	for _, files := range form.File {
		for _, fileHeader := range files {
			file, err := fileHeader.Open()
			if err != nil {
				slog.Error("Failed to open uploaded file", "error", err, "filename", h.sanitize(fileHeader.Filename)) // #nosec G706
				h.jsonError(w, fmt.Sprintf("Failed to open file: %v", err), http.StatusInternalServerError)
				return
			}
			url, err := h.Store.UploadToGCS(r.Context(), swarmID, file, fileHeader.Filename)
			if closeErr := file.Close(); closeErr != nil {
				slog.Warn("Failed to close file after upload", "error", closeErr)
			}
			if err != nil {
				slog.Error("Failed to upload file to GCS", "error", err, "filename", h.sanitize(fileHeader.Filename)) // #nosec G706
				h.jsonError(w, "Failed to upload file to storage", http.StatusInternalServerError)
				return
			}
			mediaURLs = append(mediaURLs, url)
		}
	}

	// Return the summary and UUID (no saving yet)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"referenceID":         swarmID,
		"description":         description,
		"latitude":            lat,
		"longitude":           lon,
		"nearestIntersection": nearestIntersection,
		"mediaFilenames":      mediaFilenames,
		"mediaURLs":           mediaURLs,
	}); err != nil {
		slog.Error("Failed to encode swarm summary", "error", err)
	}
}

func (h *Handlers) ConfirmSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)
	if err := r.ParseMultipartForm(maxFileSize); err != nil && err != http.ErrNotMultipart { // #nosec G120
		slog.Error("Failed to parse multipart form", "error", err)
		h.jsonError(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Validate reference ID
	swarmID := r.FormValue("referenceID")
	if swarmID == "" {
		h.jsonError(w, "Reference ID is required", http.StatusBadRequest)
		return
	}

	// Validate required fields
	description := r.FormValue("description")
	if description == "" {
		h.jsonError(w, "Description is required", http.StatusBadRequest)
		return
	}

	latitude := r.FormValue("latitude")
	longitude := r.FormValue("longitude")
	lat, lon, err := validateCoordinates(latitude, longitude)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	nearestIntersection := r.FormValue("intersection")
	if nearestIntersection == "" {
		h.jsonError(w, "Nearest intersection is required", http.StatusBadRequest)
		return
	}

	// Get contact information (optional)
	reporterName := r.FormValue("reporterName")
	reporterEmail := r.FormValue("reporterEmail")
	reporterPhone := r.FormValue("reporterPhone")
	reporterSessionID := r.FormValue("reporterSessionId")
	mediaURLs := r.Form["mediaURLs"]

	// Handle file uploads
	form := r.MultipartForm
	if form != nil && form.File != nil {
		for _, files := range form.File {
			for _, fileHeader := range files {
				file, err := fileHeader.Open()
				if err != nil {
					slog.Error("Error opening uploaded file", "error", err, "filename", h.sanitize(fileHeader.Filename)) // #nosec G706
					continue
				}
				url, err := h.Store.UploadToGCS(r.Context(), swarmID, file, fileHeader.Filename)
				if closeErr := file.Close(); closeErr != nil {
					slog.Warn("Failed to close file", "error", closeErr)
				}
				if err != nil {
					slog.Error("Error uploading file to GCS", "error", err, "filename", h.sanitize(fileHeader.Filename)) // #nosec G706
					continue
				}
				mediaURLs = append(mediaURLs, url)
			}
		}
	}

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
		ReportedMediaURLs:    mediaURLs,
		ReporterName:         reporterName,
		ReporterEmail:        reporterEmail,
		ReporterPhone:        reporterPhone,
		ReporterSessionID:    reporterSessionID,
	}

	if err := h.Store.CreateSwarm(r.Context(), report); err != nil {
		slog.Error("Error creating swarm in store", "error", err)
		h.jsonError(w, "Failed to save report", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		slog.Error("Failed to encode swarm report", "error", err)
	}
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
		h.jsonError(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to 1MB to prevent memory exhaustion (G120)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var updateReq struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		BeekeeperNotes string `json:"beekeeperNotes"`
	}

	// Try to decode JSON first
	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
			h.jsonError(w, "Invalid JSON request body", http.StatusBadRequest)
			return
		}
	} else {
		// Fallback to form values
		updateReq.ID = r.FormValue("id")
		updateReq.Status = r.FormValue("status")
		updateReq.BeekeeperNotes = r.FormValue("beekeeperNotes")
	}

	if updateReq.ID == "" || updateReq.Status == "" {
		h.jsonError(w, "Missing id or status in request", http.StatusBadRequest)
		return
	}

	currentTime := time.Now()
	var updates []firestore.Update
	updates = append(updates, firestore.Update{Path: "status", Value: updateReq.Status})
	updates = append(updates, firestore.Update{Path: "lastUpdatedTimestamp", Value: currentTime})

	if err := h.Store.UpdateSwarm(r.Context(), updateReq.ID, updates); err != nil {
		slog.Error("Failed to update report in Firestore", "error", err, "id", h.sanitize(updateReq.ID)) // #nosec G706
		h.jsonError(w, "Error updating report", http.StatusInternalServerError)
		return
	}

	// If it was a form submission, redirect back to dashboard
	if r.Header.Get("Content-Type") != "application/json" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) AssignSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Limit body to 1MB
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	swarmID := r.FormValue("swarmID")
	action := r.FormValue("action")

	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}

	var updates []firestore.Update
	switch action {
	case "assign":
		updates = append(updates, firestore.Update{Path: "assignedCollectorID", Value: session.UserID})
		updates = append(updates, firestore.Update{Path: "assignedCollectorEmail", Value: session.Username})
		updates = append(updates, firestore.Update{Path: "status", Value: "Claimed"})
	case "unassign":
		updates = append(updates, firestore.Update{Path: "assignedCollectorID", Value: ""})
		updates = append(updates, firestore.Update{Path: "assignedCollectorEmail", Value: ""})
		updates = append(updates, firestore.Update{Path: "status", Value: "Reported"})
	}
	updates = append(updates, firestore.Update{Path: "lastUpdatedTimestamp", Value: time.Now()})

	if err := h.Store.UpdateSwarm(r.Context(), swarmID, updates); err != nil {
		slog.Error("Failed to update swarm", "error", err, "id", h.sanitize(swarmID)) // #nosec G706
		http.Error(w, "Failed to update swarm", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handlers) ClaimSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Limit body to 1MB
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	swarmID := r.FormValue("swarmID")
	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}

	var updates []firestore.Update
	updates = append(updates, firestore.Update{Path: "assignedCollectorID", Value: session.UserID})
	updates = append(updates, firestore.Update{Path: "assignedCollectorEmail", Value: session.Username})
	updates = append(updates, firestore.Update{Path: "status", Value: "Claimed"})
	updates = append(updates, firestore.Update{Path: "lastUpdatedTimestamp", Value: time.Now()})

	if err := h.Store.UpdateSwarm(r.Context(), swarmID, updates); err != nil {
		slog.Error("Failed to update swarm", "error", err, "id", h.sanitize(swarmID)) // #nosec G706
		http.Error(w, "Failed to update swarm", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/swarmlist", http.StatusSeeOther)
}

func (h *Handlers) UnclaimSwarmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Limit body to 1MB
	session, ok := r.Context().Value(SessionContextKey).(*models.Session)
	if !ok {
		slog.Error("Could not retrieve session from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	swarmID := r.FormValue("swarmID")
	if swarmID == "" {
		http.Error(w, "Swarm ID required", http.StatusBadRequest)
		return
	}

	var updates []firestore.Update
	updates = append(updates, firestore.Update{Path: "assignedCollectorID", Value: ""})
	updates = append(updates, firestore.Update{Path: "assignedCollectorEmail", Value: ""})
	updates = append(updates, firestore.Update{Path: "status", Value: "Reported"})
	updates = append(updates, firestore.Update{Path: "lastUpdatedTimestamp", Value: time.Now()})

	if err := h.Store.UpdateSwarm(r.Context(), swarmID, updates); err != nil {
		slog.Error("Failed to update swarm", "error", err, "id", h.sanitize(swarmID)) // #nosec G706
		http.Error(w, "Failed to update swarm", http.StatusInternalServerError)
		return
	}

	slog.Info("Swarm unclaimed", "swarmID", h.sanitize(swarmID), "userID", h.sanitize(session.UserID)) // #nosec G706

	http.Redirect(w, r, "/swarmlist", http.StatusSeeOther)
}

func (h *Handlers) validateFile(fileHeader *multipart.FileHeader) error {
	if fileHeader.Size > maxFileSize {
		return fmt.Errorf("file %s is too large (max size is 50MB)", fileHeader.Filename)
	}

	file, err := fileHeader.Open()
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", fileHeader.Filename, err)
	}
	defer file.Close()

	// Read the first 512 bytes to detect content type
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read file %s: %v", fileHeader.Filename, err)
	}

	contentType := http.DetectContentType(buffer[:n])

	if allowedImageTypes[contentType] || allowedVideoTypes[contentType] {
		return nil
	}

	// Fallback to extension check for types not easily detected by DetectContentType
	// (like some video formats)
	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	allowedExtensions := map[string]bool{
		".heic": true, ".heif": true,
		".mp4": true, ".webm": true, ".mov": true, ".avi": true, ".3gp": true, ".mpeg": true,
		".ogv": true, ".ts": true, ".mkv": true, ".m4v": true,
	}

	if allowedExtensions[ext] {
		slog.Info("File accepted by extension", "filename", h.sanitize(fileHeader.Filename), "extension", h.sanitize(ext), "contentType", h.sanitize(contentType)) // #nosec G706
		return nil
	}

	return fmt.Errorf("file %s has unsupported type %s (extension: %s)", fileHeader.Filename, contentType, ext)
}
