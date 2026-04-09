// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

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

// MapboxLocationService implements LocationService using Mapbox Geocoding API.
type MapboxLocationService struct {
	Client      *http.Client
	AccessToken string
}

func (s *MapboxLocationService) GetNearestIntersection(ctx context.Context, lat, lon float64) (string, error) {
	if s.AccessToken == "" {
		return "", fmt.Errorf("mapbox access token is required")
	}
	url := fmt.Sprintf("https://api.mapbox.com/geocoding/v5/mapbox.places/%f,%f.json?access_token=%s&types=address,neighborhood,locality", lon, lat, s.AccessToken)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mapbox returned status %d", resp.StatusCode)
	}

	var result struct {
		Features []struct {
			PlaceName string `json:"place_name"`
		} `json:"features"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Features) > 0 {
		return result.Features[0].PlaceName, nil
	}

	return "Unknown location", nil
}

// MockLocationService is a mock implementation of LocationService for testing.
type MockLocationService struct {
	MockIntersection string
	MockError        error
}

func (m *MockLocationService) GetNearestIntersection(_ context.Context, _, _ float64) (string, error) {
	return m.MockIntersection, m.MockError
}
