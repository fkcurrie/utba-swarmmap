package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
)

func TestAdminHandler(t *testing.T) {
	mockStore := &MockStore{
		Users: []models.User{
			{ID: "user1", Email: "user1@example.com", Role: "collector"},
		},
		Swarms: []models.SwarmReport{
			{ID: "swarm1", Status: "Reported"},
		},
	}
	tmpl, _ := template.New("admin.html").Parse("<html>Admin Page</html>")
	h := &Handlers{
		Store:     mockStore,
		Templates: tmpl,
	}

	req, _ := http.NewRequest("GET", "/admin", nil)
	session := &models.Session{
		UserID:    "admin-id",
		Username:  "admin@example.com",
		Role:      "site_admin",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	ctx := context.WithValue(req.Context(), SessionContextKey, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.AdminHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestCollectorAdminHandler(t *testing.T) {
	mockStore := &MockStore{
		Users: []models.User{
			{ID: "user1", Email: "user1@example.com", Role: "collector"},
		},
	}
	tmpl, _ := template.New("collector_admin.html").Parse("<html>Collector Admin Page</html>")
	h := &Handlers{
		Store:     mockStore,
		Templates: tmpl,
	}

	req, _ := http.NewRequest("GET", "/collector_admin", nil)
	session := &models.Session{
		UserID:    "cadmin-id",
		Username:  "cadmin@example.com",
		Role:      "collector_admin",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	ctx := context.WithValue(req.Context(), SessionContextKey, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.CollectorAdminHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}
