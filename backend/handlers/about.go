// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"log/slog"
	"net/http"
	"sort"
)

type MonthGroup struct {
	Month    string
	Features []GitHubIssue
	Bugs     []GitHubIssue
}

func (h *Handlers) AboutHandler(w http.ResponseWriter, r *http.Request) {
	session := h.getSession(r)
	
	issues, err := h.GitHubService.GetClosedIssues(h.GithubRepo, h.GithubToken)
	if err != nil {
		slog.Error("Failed to fetch closed issues", "error", err)
		// Fallback to empty list or error page
		issues = []GitHubIssue{}
	}

	groups := make(map[string]*MonthGroup)
	var monthKeys []string

	for _, issue := range issues {
		// GitHub Issues API returns both issues and pull requests.
		// We only want issues.
		if issue.PullRequest != nil {
			continue
		}

		// Use ClosedAt if available, otherwise CreatedAt
		date := issue.ClosedAt
		if date.IsZero() {
			date = issue.CreatedAt
		}
		
		monthKey := date.Format("2006-01")
		if _, ok := groups[monthKey]; !ok {
			groups[monthKey] = &MonthGroup{
				Month: date.Format("January 2006"),
			}
			monthKeys = append(monthKeys, monthKey)
		}

		isBug := false
		isFeature := false
		for _, label := range issue.Labels {
			if label.Name == "bug" {
				isBug = true
			}
			if label.Name == "enhancement" {
				isFeature = true
			}
		}

		if isBug {
			groups[monthKey].Bugs = append(groups[monthKey].Bugs, issue)
		} else if isFeature {
			groups[monthKey].Features = append(groups[monthKey].Features, issue)
		}
	}

	// Sort months descending
	sort.Sort(sort.Reverse(sort.StringSlice(monthKeys)))

	var sortedGroups []*MonthGroup
	for _, key := range monthKeys {
		sortedGroups = append(sortedGroups, groups[key])
	}

	data := map[string]interface{}{
		"Title":             "About",
		"Version":           h.Version,
		"BuildDate":         h.BuildDate,
		"User":              session,
		"FrontendAssetsURL": h.FrontendAssetsURL,
		"Groups":            sortedGroups,
	}

	err = h.Templates.ExecuteTemplate(w, "about.html", data)
	if err != nil {
		slog.Error("Error executing about template", "error", err)
		http.Error(w, "Failed to render about page", http.StatusInternalServerError)
		return
	}
}
