package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
)

func TestGetSwarms_Contract(t *testing.T) {
	mockStore := &MockStore{
		Swarms: []models.SwarmReport{
			{
				ID:                  "1",
				Description:         "Test Description",
				Status:              "Reported",
				DisplayStatus:       "Reported",
				Latitude:            43.6532,
				Longitude:           -79.3832,
				NearestIntersection: "Yonge & Bloor",
				ReportedTimestamp:   time.Now(),
			},
		},
	}
	h := &Handlers{Store: mockStore}

	req, _ := http.NewRequest("GET", "/get_swarms", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.GetSwarmsHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	var swarms []map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&swarms); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if len(swarms) == 0 {
		t.Fatal("expected at least one swarm")
	}

	// Verify contract (fields the frontend expects)
	expectedFields := []string{
		"latitude", "longitude", "displayStatus", "nearestIntersection", "reportedTimestamp", "description",
	}

	for _, field := range expectedFields {
		if _, ok := swarms[0][field]; !ok {
			t.Errorf("missing field in response: %s", field)
		}
	}
}

func TestPrepareSwarm_Contract(t *testing.T) {
	// Add similar contract test for PrepareSwarm
}
