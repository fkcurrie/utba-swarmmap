// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticFiles(t *testing.T) {
	// Create a temporary static directory
	tmpDir, err := os.MkdirTemp("", "static-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test file
	cssDir := filepath.Join(tmpDir, "css")
	if err := os.Mkdir(cssDir, 0755); err != nil {
		t.Fatal(err)
	}
	testCSS := "body { color: red; }"
	if err := os.WriteFile(filepath.Join(cssDir, "style.css"), []byte(testCSS), 0644); err != nil {
		t.Fatal(err)
	}

	// Setup mux like in main.go
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir(tmpDir))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Test requesting the file
	req, err := http.NewRequest("GET", "/static/css/style.css", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if body := rr.Body.String(); body != testCSS {
		t.Errorf("handler returned unexpected body: got %v want %v", body, testCSS)
	}
}
