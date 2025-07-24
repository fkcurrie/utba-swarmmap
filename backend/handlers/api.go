package handlers

import (
	"encoding/json"
	"log"
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
		log.Printf("Error getting visit counts: %v", err)
		http.Error(w, "Failed to retrieve visit data", http.StatusInternalServerError)
		return
	}

	visitsJSON, err := json.Marshal(visits)
	if err != nil {
		log.Printf("Error marshalling visits to JSON: %v", err)
		http.Error(w, "Failed to process visit data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(visitsJSON)
}

func (h *Handlers) TrackVisitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		VisitorID string `json:"visitorId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if reqBody.VisitorID == "" {
		http.Error(w, "Visitor ID is required", http.StatusBadRequest)
		return
	}

	if err := h.Store.TrackVisit(r.Context(), reqBody.VisitorID); err != nil {
		log.Printf("Failed to track visit: %v", err)
		http.Error(w, "Failed to track visit", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
