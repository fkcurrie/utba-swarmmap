package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// LocationService defines the interface for location-related operations.
type LocationService interface {
	GetNearestIntersection(ctx context.Context, lat, lon float64) (string, error)
}

// NominatimLocationService implements LocationService using OpenStreetMap Nominatim.
type NominatimLocationService struct {
	Client  *http.Client
	BaseURL string
}

func (s *NominatimLocationService) GetNearestIntersection(ctx context.Context, lat, lon float64) (string, error) {
	baseURL := s.BaseURL
	if baseURL == "" {
		baseURL = "https://nominatim.openstreetmap.org"
	}
	url := fmt.Sprintf("%s/reverse?format=json&lat=%f&lon=%f", baseURL, lat, lon)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "utba-swarmmap (fkcurrie/utba-swarmmap)")

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("nominatim returned status %d", resp.StatusCode)
	}

	var result struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.DisplayName, nil
}

// MockLocationService is a mock implementation of LocationService for testing.
type MockLocationService struct {
	MockIntersection string
	MockError        error
}

func (m *MockLocationService) GetNearestIntersection(_ context.Context, _, _ float64) (string, error) {
	return m.MockIntersection, m.MockError
}
