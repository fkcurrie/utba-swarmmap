// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/fkcurrie/utba-swarmmap/service"
)

func TestSwarmListHandler(t *testing.T) {
	mockStore := &MockStore{}
	tmpl, _ := template.New("swarmlist.html").Parse("<html>Swarm List</html>")
	h := &Handlers{
		Store:        mockStore,
		Templates:    tmpl,
		SwarmService: service.NewSwarmService(mockStore),
	}

	req, _ := http.NewRequest("GET", "/swarmlist", nil)
	session := &models.Session{Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)}
	ctx := context.WithValue(req.Context(), SessionContextKey, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.SwarmListHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestCollectorsMapHandler(t *testing.T) {
	mockStore := &MockStore{}
	tmpl, _ := template.New("collectors_map.html").Parse("<html>Collectors Map</html>")
	h := &Handlers{Store: mockStore, Templates: tmpl}

	req, _ := http.NewRequest("GET", "/collectorsmap", nil)
	session := &models.Session{Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)}
	ctx := context.WithValue(req.Context(), SessionContextKey, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.CollectorsMapHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestDashboardHandler(t *testing.T) {
	mockStore := &MockStore{}
	tmpl, _ := template.New("dashboard.html").Parse("<html>Dashboard</html>")
	h := &Handlers{Store: mockStore, Templates: tmpl}

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	session := &models.Session{Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)}
	ctx := context.WithValue(req.Context(), SessionContextKey, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.DashboardHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestLoginPageHandler(t *testing.T) {
	tmpl, _ := template.New("login.html").Parse("<html>Login</html>")
	h := &Handlers{Templates: tmpl}

	req, _ := http.NewRequest("GET", "/login", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.LoginPageHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestRegisterPageHandler(t *testing.T) {
	tmpl, _ := template.New("register.html").Parse("<html>Register</html>")
	h := &Handlers{Templates: tmpl}

	req, _ := http.NewRequest("GET", "/register", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.RegisterPageHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}
