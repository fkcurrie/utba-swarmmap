// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNominatimLocationService_GetNearestIntersection_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"display_name": "Yonge & Bloor, Toronto, ON"}`)
	}))
	defer server.Close()

	service := &NominatimLocationService{
		Client:  server.Client(),
		BaseURL: server.URL,
	}

	res, err := service.GetNearestIntersection(context.Background(), 43.6532, -79.3832)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if res != "Yonge & Bloor, Toronto, ON" {
		t.Errorf("expected 'Yonge & Bloor, Toronto, ON', got '%s'", res)
	}
}

func TestMapboxLocationService_GetNearestIntersection_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"features": [{"place_name": "Yonge & Bloor, Toronto, ON"}]}`)
	}))
	defer server.Close()

	service := &MapboxLocationService{
		Client:      server.Client(),
		BaseURL:     server.URL,
		AccessToken: "test-token",
	}

	res, err := service.GetNearestIntersection(context.Background(), 43.6532, -79.3832)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if res != "Yonge & Bloor, Toronto, ON" {
		t.Errorf("expected 'Yonge & Bloor, Toronto, ON', got '%s'", res)
	}
}

func TestMapboxLocationService_GetNearestIntersection_NoToken(t *testing.T) {
	service := &MapboxLocationService{
		AccessToken: "",
	}

	_, err := service.GetNearestIntersection(context.Background(), 0, 0)
	if err == nil {
		t.Fatal("expected error due to missing token, got nil")
	}
}

func TestMapboxLocationService_GetNearestIntersection_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	service := &MapboxLocationService{
		Client:      server.Client(),
		BaseURL:     server.URL,
		AccessToken: "test-token",
	}

	_, err := service.GetNearestIntersection(context.Background(), 0, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNominatimLocationService_GetNearestIntersection_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	service := &NominatimLocationService{
		Client:  server.Client(),
		BaseURL: server.URL,
	}

	_, err := service.GetNearestIntersection(context.Background(), 0, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestMockLocationService(t *testing.T) {
	mock := &MockLocationService{
		MockIntersection: "Test Intersection",
	}

	res, err := mock.GetNearestIntersection(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res != "Test Intersection" {
		t.Errorf("expected 'Test Intersection', got '%s'", res)
	}

	mock.MockError = fmt.Errorf("test error")
	_, err = mock.GetNearestIntersection(context.Background(), 0, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
