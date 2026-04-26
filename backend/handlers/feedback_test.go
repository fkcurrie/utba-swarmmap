// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type MockGitHubService struct {
	LastRepo     string
	LastToken    string
	LastTitle    string
	LastBody     string
	LastLabels   []string
	ReturnErr    error
	ReturnIssues []GitHubIssue
}

func (m *MockGitHubService) CreateIssue(repo, token, title, body string, labels []string) error {
	m.LastRepo = repo
	m.LastToken = token
	m.LastTitle = title
	m.LastBody = body
	m.LastLabels = labels
	return m.ReturnErr
}

func (m *MockGitHubService) GetClosedIssues(repo, token string) ([]GitHubIssue, error) {
	m.LastRepo = repo
	m.LastToken = token
	return m.ReturnIssues, m.ReturnErr
}

type MockAIService struct {
	InterpretedBody string
	ReturnErr       error
}

func (m *MockAIService) InterpretFeedback(_ context.Context, _, _ string, _ FeedbackContext) (string, error) {
	return m.InterpretedBody, m.ReturnErr
}

func TestFeedbackHandler_Success(t *testing.T) {
	mockGitHub := &MockGitHubService{}
	h := &Handlers{
		GitHubService: mockGitHub,
		GithubToken:   "test-token",
		GithubRepo:    "test/repo",
	}

	payload := FeedbackRequest{
		Type:        "bug",
		Title:       "Test Bug",
		Description: "Something is broken",
		Context: FeedbackContext{
			URL:      "http://localhost/test",
			Browser:  "Test Browser",
			LoggedIn: true,
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/feedback", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.FeedbackHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if mockGitHub.LastTitle != "Test Bug" {
		t.Errorf("expected title %v, got %v", "Test Bug", mockGitHub.LastTitle)
	}
	if mockGitHub.LastLabels[0] != "repo-agent" || mockGitHub.LastLabels[1] != "bug" {
		t.Errorf("unexpected labels: %v", mockGitHub.LastLabels)
	}
}

func TestFeedbackHandler_AISuccess(t *testing.T) {
	mockGitHub := &MockGitHubService{}
	mockAI := &MockAIService{
		InterpretedBody: "Interpreted AI Body",
	}
	h := &Handlers{
		GitHubService: mockGitHub,
		AIService:     mockAI,
		GithubToken:   "test-token",
		GithubRepo:    "test/repo",
	}

	payload := FeedbackRequest{
		Type:        "bug",
		Title:       "Test AI",
		Description: "Raw feedback",
		Context: FeedbackContext{
			URL:      "http://localhost/test",
			Browser:  "Test Browser",
			LoggedIn: true,
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/feedback", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.FeedbackHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if mockGitHub.LastBody != "Interpreted AI Body" {
		t.Errorf("expected body %v, got %v", "Interpreted AI Body", mockGitHub.LastBody)
	}
}

func TestFeedbackHandler_NoToken(t *testing.T) {
	h := &Handlers{
		GithubToken: "",
	}

	payload := FeedbackRequest{
		Type:        "bug",
		Title:       "Test Bug",
		Description: "Something is broken",
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/feedback", bytes.NewBuffer(body))

	rr := httptest.NewRecorder()
	h.FeedbackHandler(rr, req)

	if status := rr.Code; status != http.StatusServiceUnavailable {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusServiceUnavailable)
	}
}

func TestFeedbackHandler_GitHubError(t *testing.T) {
	mockGitHub := &MockGitHubService{
		ReturnErr: errors.New("github api error"),
	}
	h := &Handlers{
		GitHubService: mockGitHub,
		GithubToken:   "test-token",
	}

	payload := FeedbackRequest{
		Type:        "bug",
		Title:       "Test Bug",
		Description: "Something is broken",
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/feedback", bytes.NewBuffer(body))

	rr := httptest.NewRecorder()
	h.FeedbackHandler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
	}
}
