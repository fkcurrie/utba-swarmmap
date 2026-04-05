package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/google/uuid"
)

func (h *Handlers) GenerateSampleDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestData map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			h.jsonError(w, "Session ID required", http.StatusBadRequest)
			return
		}
		requestData = map[string]interface{}{"sessionId": sessionID}
	}

	sessionID, ok := requestData["sessionId"].(string)
	if !ok || sessionID == "" {
		h.jsonError(w, "Session ID required in request", http.StatusBadRequest)
		return
	}

	slog.Info("Generating sample swarms", "sessionID", sessionID)

	now := time.Now()
	sampleSwarms := []models.SwarmReport{
		{
			ID:                  uuid.New().String(),
			Description:         "Large swarm on oak tree branch",
			Status:              "Reported",
			Latitude:            43.6532,
			Longitude:           -79.3832,
			NearestIntersection: "Yonge & Bloor",
			ReportedTimestamp:   now.Add(-2 * time.Hour),
			ReporterSessionID:   sessionID,
		},
		{
			ID:                  uuid.New().String(),
			Description:         "Medium-sized swarm on fence post",
			Status:              "Verified",
			Latitude:            43.6629,
			Longitude:           -79.3957,
			NearestIntersection: "Bathurst & Dupont",
			ReportedTimestamp:   now.Add(-6 * time.Hour),
			ReporterSessionID:   sessionID,
		},
	}

	var createdSwarms []models.SwarmReport
	for _, swarm := range sampleSwarms {
		if err := h.Store.CreateSwarm(r.Context(), swarm); err != nil {
			slog.Error("Failed to create sample swarm", "swarmID", swarm.ID, "error", err)
			continue
		}
		createdSwarms = append(createdSwarms, swarm)
	}

	response := map[string]interface{}{
		"success":       true,
		"created_count": len(createdSwarms),
		"message":       fmt.Sprintf("Generated %d sample swarms", len(createdSwarms)),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode demo response", "error", err)
	}
}
