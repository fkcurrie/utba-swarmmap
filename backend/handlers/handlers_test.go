package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/fkcurrie/utba-swarmmap/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// MockStore is a mock implementation of the Storer interface for testing.
type MockStore struct {
	Swarms      []models.SwarmReport
	Users       []models.User
	Sessions    map[string]models.Session
	ReturnError bool
}

func (m *MockStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if m.ReturnError {
		return nil, http.ErrHandlerTimeout
	}
	for _, user := range m.Users {
		if user.Email == email {
			return &user, nil
		}
	}
	return nil, nil // Not found
}

func (m *MockStore) CreateUser(ctx context.Context, user models.User) (string, error) {
	if m.ReturnError {
		return "", http.ErrHandlerTimeout
	}
	user.ID = "new-user-id"
	m.Users = append(m.Users, user)
	return user.ID, nil
}

func (m *MockStore) GetSession(ctx context.Context, sessionID string) (*models.Session, error) {
	if m.ReturnError {
		return nil, http.ErrHandlerTimeout
	}
	session, ok := m.Sessions[sessionID]
	if !ok {
		return nil, nil // Not found
	}
	return &session, nil
}

func (m *MockStore) CreateSession(ctx context.Context, session models.Session) (string, error) {
	if m.ReturnError {
		return "", http.ErrHandlerTimeout
	}
	if m.Sessions == nil {
		m.Sessions = make(map[string]models.Session)
	}
	sessionID := "new-session-id"
	m.Sessions[sessionID] = session
	return sessionID, nil
}

func (m *MockStore) DeleteSession(ctx context.Context, sessionID string) error {
	if m.ReturnError {
		return http.ErrHandlerTimeout
	}
	delete(m.Sessions, sessionID)
	return nil
}

func (m *MockStore) CreateSwarm(ctx context.Context, swarm models.SwarmReport) error {
	if m.ReturnError {
		return http.ErrHandlerTimeout
	}
	m.Swarms = append(m.Swarms, swarm)
	return nil
}

func (m *MockStore) DeleteSwarm(ctx context.Context, swarmID string) error {
	if m.ReturnError {
		return http.ErrHandlerTimeout
	}
	for i, swarm := range m.Swarms {
		if swarm.ID == swarmID {
			m.Swarms = append(m.Swarms[:i], m.Swarms[i+1:]...)
			return nil
		}
	}
	return nil // Swarm not found
}

func (m *MockStore) DeleteUser(ctx context.Context, userID string) error {
	if m.ReturnError {
		return http.ErrHandlerTimeout
	}
	for i, user := range m.Users {
		if user.ID == userID {
			m.Users = append(m.Users[:i], m.Users[i+1:]...)
			return nil
		}
	}
	return nil // User not found
}

func (m *MockStore) UpdateSwarm(ctx context.Context, swarmID string, updates []firestore.Update) error {
	if m.ReturnError {
		return http.ErrHandlerTimeout
	}
	for i, swarm := range m.Swarms {
		if swarm.ID == swarmID {
			for _, update := range updates {
				if update.Path == "status" {
					m.Swarms[i].Status = update.Value.(string)
				}
				if update.Path == "assignedCollectorID" {
					m.Swarms[i].AssignedCollectorID = update.Value.(string)
				}
			}
			return nil
		}
	}
	return nil // Swarm not found
}

func (m *MockStore) UpdateUser(ctx context.Context, userID string, updates []firestore.Update) error {
	if m.ReturnError {
		return http.ErrHandlerTimeout
	}
	for i, user := range m.Users {
		if user.ID == userID {
			for _, update := range updates {
				if update.Path == "status" {
					m.Users[i].Status = update.Value.(string)
				}
				if update.Path == "role" {
					m.Users[i].Role = update.Value.(string)
				}
			}
			return nil
		}
	}
	return nil // User not found
}

func (m *MockStore) GetAllUsers(ctx context.Context) ([]models.User, error) {
	if m.ReturnError {
		return nil, http.ErrHandlerTimeout
	}
	return m.Users, nil
}

func (m *MockStore) TrackVisit(ctx context.Context, visitorID string) error {
	if m.ReturnError {
		return http.ErrHandlerTimeout
	}
	// Simplified mock implementation
	return nil
}

func (m *MockStore) GetVisitCounts(ctx context.Context, days int) (map[string]int, error) {
	if m.ReturnError {
		return nil, http.ErrHandlerTimeout
	}
	// Simplified mock implementation
	return map[string]int{"2025-07-23": 1}, nil
}

func (m *MockStore) GetAllSwarms(ctx context.Context) ([]models.SwarmReport, error) {
	if m.ReturnError {
		return nil, http.ErrHandlerTimeout // Simulate a database error
	}
	return m.Swarms, nil
}



func (m *MockStore) GetSwarmsBySessionID(ctx context.Context, sessionID string) ([]models.SwarmReport, error) {
	if m.ReturnError {
		return nil, http.ErrHandlerTimeout
	}
	var userSwarms []models.SwarmReport
	for _, swarm := range m.Swarms {
		if swarm.ReporterSessionID == sessionID {
			userSwarms = append(userSwarms, swarm)
		}
	}
	return userSwarms, nil
}

func TestGetSwarmsHandler_WithSwarms(t *testing.T) {
	// Prepare a mock store with some data
	mockSwarms := []models.SwarmReport{
		{ID: "1", Description: "Swarm 1", Status: "Reported", ReportedTimestamp: time.Now()},
		{ID: "2", Description: "Swarm 2", Status: "Captured", ReportedTimestamp: time.Now().Add(-25 * time.Hour)},
	}
	mockStore := &MockStore{Swarms: mockSwarms}

	// Initialize handlers with the mock store
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/get_swarms", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.GetSwarmsHandler)
	handler.ServeHTTP(rr, req)

	// Check status code and content type
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v", ctype, "application/json")
	}

	// Check the response body
	var returnedSwarms []models.SwarmReport
	if err := json.NewDecoder(rr.Body).Decode(&returnedSwarms); err != nil {
		t.Fatalf("could not decode response body: %v", err)
	}

	if len(returnedSwarms) != 2 {
		t.Errorf("handler returned wrong number of swarms: got %d want %d", len(returnedSwarms), 2)
	}

	// Check the dynamic DisplayStatus logic
	if returnedSwarms[0].DisplayStatus != "Reported" {
		t.Errorf("expected DisplayStatus to be 'Reported', got '%s'", returnedSwarms[0].DisplayStatus)
	}
	if returnedSwarms[1].DisplayStatus != "Captured" {
		t.Errorf("expected DisplayStatus to be 'Captured', got '%s'", returnedSwarms[1].DisplayStatus)
	}
}

func TestLoginHandler(t *testing.T) {
	h := &Handlers{
		GoogleOAuthConfig: &oauth2.Config{
			RedirectURL:  "http://localhost/auth/google/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Scopes:       []string{"email", "profile"},
			Endpoint:     google.Endpoint,
		},
	}

	req, err := http.NewRequest("GET", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.GoogleLoginHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusTemporaryRedirect {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusTemporaryRedirect)
	}
}

func TestGoogleCallbackHandler_InvalidState(t *testing.T) {
	h := &Handlers{} // No dependencies needed for this specific test case

	req, err := http.NewRequest("GET", "/auth/google/callback?state=", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.GoogleCallbackHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestDashboardHandler_Unauthenticated(t *testing.T) {
	// No session in the mock store
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	// We wrap the handler in the middleware for a complete test
	handler := h.RequireAuth(http.HandlerFunc(h.DashboardHandler))
	handler.ServeHTTP(rr, req)

	// Expect a redirect to the login page
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}
}

func TestLogoutHandler(t *testing.T) {
	mockStore := &MockStore{
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "test-user"},
		},
	}
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.LogoutHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}

	// Check that the session was deleted
	if _, ok := mockStore.Sessions["test-session-id"]; ok {
		t.Error("session was not deleted from the store")
	}
}

func TestAuthHandler_Authenticated(t *testing.T) {
	mockStore := &MockStore{
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "test-user", Username: "test@example.com", Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode response: %v", err)
	}

	if auth, ok := resp["authenticated"].(bool); !ok || !auth {
		t.Error("expected authenticated to be true")
	}
}

func TestPrepareSwarmHandler_ValidRequest(t *testing.T) {
	h := &Handlers{} // No store needed for this handler

	// Create a multipart form request
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	writer.WriteField("description", "A test swarm")
	writer.WriteField("latitude", "43.6532")
	writer.WriteField("longitude", "-79.3832")
	writer.WriteField("intersection", "Yonge & Bloor")
	// Create a dummy file part
	part, _ := writer.CreateFormFile("media", "test.jpg")
	part.Write([]byte("dummy image data"))
	writer.Close()

	req, err := http.NewRequest("POST", "/prepare_swarm", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.PrepareSwarmHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode response: %v", err)
	}

	if _, ok := resp["referenceID"]; !ok {
		t.Error("expected referenceID in response")
	}
}

func TestConfirmSwarmHandler_ValidRequest(t *testing.T) {
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	// Create a multipart form request
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	writer.WriteField("referenceID", "test-swarm-id")
	writer.WriteField("description", "A test swarm")
	writer.WriteField("latitude", "43.6532")
	writer.WriteField("longitude", "-79.3832")
	writer.WriteField("intersection", "Yonge & Bloor")
	part, _ := writer.CreateFormFile("media", "test.jpg")
	part.Write([]byte("dummy image data"))
	writer.Close()

	req, err := http.NewRequest("POST", "/confirm_swarm", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ConfirmSwarmHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestSwarmListHandler_Unauthenticated(t *testing.T) {
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/swarmlist", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(http.HandlerFunc(h.SwarmListHandler))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}
}

func TestCollectorsMapHandler_Unauthenticated(t *testing.T) {
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/collectorsmap", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(http.HandlerFunc(h.CollectorsMapHandler))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}
}

func TestAdminHandler_Unauthorized(t *testing.T) {
	mockStore := &MockStore{
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "test-user", Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.AdminHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}
}

func TestGenerateSampleDataHandler(t *testing.T) {
	mockStore := &MockStore{}
	h := &Handlers{Store: mockStore}

	// Create a request with a session ID in the body
	body := strings.NewReader(`{"sessionId": "test-session-id"}`)
	req, err := http.NewRequest("POST", "/demo/generate_sample_data", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.GenerateSampleDataHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check that swarms were created
	if len(mockStore.Swarms) == 0 {
		t.Error("expected sample swarms to be created")
	}
}

func TestApproveUserHandler(t *testing.T) {
	mockStore := &MockStore{
		Users: []models.User{
			{ID: "test-user-id", Status: "pending"},
		},
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "admin-user", Role: "site_admin", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	body := strings.NewReader("userID=test-user-id")
	req, err := http.NewRequest("POST", "/admin/approve_user", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.ApproveUserHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}

	if mockStore.Users[0].Status != "approved" {
		t.Error("expected user status to be approved")
	}
}

func TestRejectUserHandler(t *testing.T) {
	mockStore := &MockStore{
		Users: []models.User{
			{ID: "test-user-id", Status: "pending"},
		},
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "admin-user", Role: "site_admin", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	body := strings.NewReader("userID=test-user-id")
	req, err := http.NewRequest("POST", "/admin/reject_user", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.RejectUserHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}

	if len(mockStore.Users) != 0 {
		t.Error("expected user to be deleted")
	}
}

func TestDeleteSwarmHandler(t *testing.T) {
	mockStore := &MockStore{
		Swarms: []models.SwarmReport{
			{ID: "test-swarm-id"},
		},
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "admin-user", Role: "site_admin", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	body := strings.NewReader("swarmID=test-swarm-id")
	req, err := http.NewRequest("POST", "/admin/delete_swarm", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.DeleteSwarmHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}

	if len(mockStore.Swarms) != 0 {
		t.Error("expected swarm to be deleted")
	}
}

func TestPromoteUserHandler(t *testing.T) {
	mockStore := &MockStore{
		Users: []models.User{
			{ID: "test-user-id", Role: "collector"},
		},
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "admin-user", Role: "site_admin", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	body := strings.NewReader("userID=test-user-id&role=collector_admin")
	req, err := http.NewRequest("POST", "/admin/promote_user", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("site_admin", http.HandlerFunc(h.PromoteUserHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}

	if mockStore.Users[0].Role != "collector_admin" {
		t.Error("expected user role to be updated")
	}
}

func TestUpdateSwarmStatusHandler(t *testing.T) {
	mockStore := &MockStore{
		Swarms: []models.SwarmReport{
			{ID: "test-swarm-id", Status: "Reported"},
		},
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "test-user", Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	body := strings.NewReader(`{"id": "test-swarm-id", "status": "Verified"}`)
	req, err := http.NewRequest("POST", "/update_swarm_status", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("collector", http.HandlerFunc(h.UpdateSwarmStatusHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if mockStore.Swarms[0].Status != "Verified" {
		t.Error("expected swarm status to be updated")
	}
}

func TestAssignSwarmHandler(t *testing.T) {
	mockStore := &MockStore{
		Swarms: []models.SwarmReport{
			{ID: "test-swarm-id"},
		},
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "test-user", Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	body := strings.NewReader("swarmID=test-swarm-id&action=assign")
	req, err := http.NewRequest("POST", "/assign_swarm", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("collector", http.HandlerFunc(h.AssignSwarmHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}

	if mockStore.Swarms[0].AssignedCollectorID != "test-user" {
		t.Error("expected swarm to be assigned to the user")
	}
}

func TestCollectorAdminHandler_Unauthorized(t *testing.T) {
	mockStore := &MockStore{
		Sessions: map[string]models.Session{
			"test-session-id": {UserID: "test-user", Role: "collector", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	h := &Handlers{Store: mockStore}

	req, err := http.NewRequest("GET", "/collector_admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session-id"})

	rr := httptest.NewRecorder()
	handler := h.RequireAuth(h.RequireRole("collector_admin", http.HandlerFunc(h.CollectorAdminHandler)))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}
}
