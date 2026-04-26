
package handlers

import (
	"html/template"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestTemplatesRender(t *testing.T) {
	// Root of the repo is 2 levels up from backend/handlers/template_test.go
	// But during tests, the working directory is the package directory.
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}).ParseGlob(filepath.Join("..", "templates", "*.html"))
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	h := &Handlers{
		Templates: tmpl,
		Version:   "test",
		BuildDate: "now",
	}

	testCases := []struct {
		name     string
		template string
		data     map[string]interface{}
	}{
		{"index", "index.html", map[string]interface{}{"Title": "Home", "User": nil}},
		{"login", "login.html", map[string]interface{}{"Title": "Login"}},
		{"register", "register.html", map[string]interface{}{"Title": "Register"}},
		{"dashboard", "dashboard.html", map[string]interface{}{"Title": "Dashboard", "User": nil}},
		{"swarmlist", "swarmlist.html", map[string]interface{}{"Title": "Swarm List", "User": nil, "Swarms": nil}},
		{"admin", "admin.html", map[string]interface{}{"Title": "Admin", "User": nil, "PendingUsers": nil, "AllUsers": nil, "AllSwarms": nil}},
		{"collector_admin", "collector_admin.html", map[string]interface{}{"Title": "Collector Admin", "User": nil, "PendingUsers": nil, "AllCollectors": nil}},
		{"forgot_password", "forgot-password.html", map[string]interface{}{"Title": "Forgot Password"}},
		{"reset_password", "reset-password.html", map[string]interface{}{"Title": "Reset Password"}},
		{"pending_approval", "pending-approval.html", map[string]interface{}{"Title": "Pending Approval"}},
		{"message", "message.html", map[string]interface{}{"Title": "Message", "Message": "Test"}},
		{"collectors_map", "collectors_map.html", map[string]interface{}{"Title": "Collectors Map", "User": nil}},
		{"bootstrap", "bootstrap.html", map[string]interface{}{"Title": "Bootstrap"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			err := h.Templates.ExecuteTemplate(rr, tc.template, tc.data)
			if err != nil {
				t.Errorf("Failed to execute template %s: %v", tc.template, err)
			}
		})
	}
}
