// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAboutHandler(t *testing.T) {
	now := time.Now()
	mockGitHub := &MockGitHubService{
		ReturnIssues: []GitHubIssue{
			{
				Title: "New Feature",
				Labels: []struct {
					Name string `json:"name"`
				}{
					{Name: "enhancement"},
				},
				CreatedAt: now,
			},
			{
				Title: "Bug Fix",
				Labels: []struct {
					Name string `json:"name"`
				}{
					{Name: "bug"},
				},
				CreatedAt: now,
			},
			{
				Title: "Ignored PR",
				PullRequest: map[string]interface{}{"url": "http://example.com"},
				Labels: []struct {
					Name string `json:"name"`
				}{
					{Name: "enhancement"},
				},
				CreatedAt: now,
			},
		},
	}
	
	// Create a template with both about.html and header.html/footer.html if needed, 
	// but for this test, a simple template named about.html is enough as we are 
	// only testing the handler logic and execution of the main template.
	tmpl, err := template.New("about.html").Parse("<html>{{.Title}} - {{len .Groups}} groups</html>")
	if err != nil {
		t.Fatalf("Error parsing template: %v", err)
	}

	h := &Handlers{
		GitHubService: mockGitHub,
		Templates:     tmpl,
	}

	req, err := http.NewRequest("GET", "/about", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.AboutHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	
	expected := "About - 1 groups"
	if !contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func contains(s, substr string) bool {
	return (s != "" && substr != "" && (len(s) >= len(substr)) && (s[0:len(substr)] == substr || contains(s[1:], substr)))
}
