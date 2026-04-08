// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/fkcurrie/utba-swarmmap/service"
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
	h := &Handlers{
		Store:        mockStore,
		SwarmService: service.NewSwarmService(mockStore),
	}

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
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	// Prepare multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("description", "Test Description")
	_ = writer.WriteField("latitude", "43.6532")
	_ = writer.WriteField("longitude", "-79.3832")
	_ = writer.WriteField("intersection", "Yonge & Bloor")

	// Add a dummy file
	part, _ := writer.CreateFormFile("file", "test.jpg")
	_, _ = part.Write([]byte("dummy image content"))
	_ = writer.Close()

	req, _ := http.NewRequest("POST", "/prepare_swarm", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.PrepareSwarmHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", status, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	// Verify contract
	expectedFields := []string{
		"referenceID", "description", "latitude", "longitude", "nearestIntersection", "mediaFilenames", "mediaURLs",
	}

	for _, field := range expectedFields {
		if _, ok := response[field]; !ok {
			t.Errorf("missing field in response: %s", field)
		}
	}
}
