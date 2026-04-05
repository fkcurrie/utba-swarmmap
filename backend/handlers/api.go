package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func (h *Handlers) VisitsAPIHandler(w http.ResponseWriter, r *http.Request) {
	rangeStr := r.URL.Query().Get("range")
	days := 7 // Default to 7 days
	switch rangeStr {
	case "24h":
		days = 1
	case "30d":
		days = 30
	case "60d":
		days = 60
	case "6m":
		days = 180
	case "12m":
		days = 365
	}

	visits, err := h.Store.GetVisitCounts(r.Context(), days)
	if err != nil {
		slog.Error("Error getting visit counts", "error", err)
		h.jsonError(w, "Failed to retrieve visit data", http.StatusInternalServerError)
		return
	}

	visitsJSON, err := json.Marshal(visits)
	if err != nil {
		slog.Error("Error marshalling visits to JSON", "error", err)
		h.jsonError(w, "Failed to process visit data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(visitsJSON); err != nil {
		slog.Error("Failed to write visits response", "error", err)
	}
}

func (h *Handlers) TrackVisitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		VisitorID string `json:"visitorId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if reqBody.VisitorID == "" {
		h.jsonError(w, "Visitor ID is required", http.StatusBadRequest)
		return
	}

	if err := h.Store.TrackVisit(r.Context(), reqBody.VisitorID); err != nil {
		slog.Error("Failed to track visit", "error", err)
		h.jsonError(w, "Failed to track visit", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
