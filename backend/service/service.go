// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package service

import (
	"context"
	"time"

	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/fkcurrie/utba-swarmmap/store"
)

// SwarmService defines the business logic for swarm operations.
type SwarmService interface {
	GetSwarms(ctx context.Context, sessionID string, user *models.Session) ([]models.SwarmReport, error)
	// Add other methods here as we refactor
}

type swarmService struct {
	store store.Storer
}

// NewSwarmService creates a new SwarmService.
func NewSwarmService(s store.Storer) SwarmService {
	return &swarmService{
		store: s,
	}
}

func (s *swarmService) GetSwarms(ctx context.Context, sessionID string, session *models.Session) ([]models.SwarmReport, error) {
	var currentReports []models.SwarmReport
	var err error

	isCollector := session != nil && (session.Role == "collector" || session.Role == "collector_admin" || session.Role == "site_admin")

	if isCollector && sessionID == "" {
		currentReports, err = s.store.GetAllSwarms(ctx)
	} else if sessionID != "" {
		currentReports, err = s.store.GetSwarmsBySessionID(ctx, sessionID)
	} else {
		// Public request: return nothing to protect privacy and prevent unauthorized interference.
		// In the future, this could return a "general overview" (e.g. counts per region)
		return []models.SwarmReport{}, nil
	}

	if err != nil {
		return nil, err
	}

	for i := range currentReports {
		currentReports[i].DisplayStatus = currentReports[i].Status
		if currentReports[i].Status != "Captured" && time.Since(currentReports[i].ReportedTimestamp).Hours() > 24 {
			currentReports[i].DisplayStatus = "Archived"
		}

		// Privacy: Clear reporter details if not a collector/admin
		if !isCollector {
			currentReports[i].ReporterName = ""
			currentReports[i].ReporterEmail = ""
			currentReports[i].ReporterPhone = ""
			currentReports[i].ReporterSessionID = ""
		}
	}

	return currentReports, nil
}
