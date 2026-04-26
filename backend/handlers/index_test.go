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

	// Test HEAD request
	reqHEAD, err := http.NewRequest("HEAD", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rrHEAD := httptest.NewRecorder()
	handler.ServeHTTP(rrHEAD, reqHEAD)

	if status := rrHEAD.Code; status != http.StatusOK {
		t.Errorf("HEAD request returned wrong status code: got %v want %v",
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
