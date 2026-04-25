// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIndexHandler(t *testing.T) {
	mockStore := &MockStore{}
	tmpl, err := template.New("index.html").Parse("<html>{{.Title}}</html>")
	if err != nil {
		t.Fatalf("Error parsing template: %v", err)
	}

	h := &Handlers{
		Store:     mockStore,
		Templates: tmpl,
	}

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.IndexHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestIndexHandler_NotFound(t *testing.T) {
	h := &Handlers{}

	req, err := http.NewRequest("GET", "/notfound", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.IndexHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusNotFound)
	}
}

func TestIndexHandler_Methods(t *testing.T) {
	mockStore := &MockStore{}
	h := &Handlers{
		Store:     mockStore,
		Templates: template.Must(template.New("index.html").Parse("{{.Title}}")),
	}

	// Test HEAD request
	req, _ := http.NewRequest("HEAD", "/", nil)
	rr := httptest.NewRecorder()
	http.HandlerFunc(h.IndexHandler).ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("HEAD request failed: got %v want %v", status, http.StatusOK)
	}

	// Test POST request (should be 405)
	req, _ = http.NewRequest("POST", "/", nil)
	rr = httptest.NewRecorder()
	http.HandlerFunc(h.IndexHandler).ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("POST request on root should be 405: got %v want %v", status, http.StatusMethodNotAllowed)
	}
}
