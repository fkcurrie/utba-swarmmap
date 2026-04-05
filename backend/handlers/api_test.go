package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrackVisitHandler(t *testing.T) {
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	payload := map[string]string{"visitorId": "test-visitor"}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/track_visit", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.TrackVisitHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestVisitsAPIHandler(t *testing.T) {
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	req, _ := http.NewRequest("GET", "/api/visits", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.VisitsAPIHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var resp map[string]int
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode response: %v", err)
	}

	if len(resp) == 0 {
		t.Error("expected visit counts, got empty map")
	}
}
