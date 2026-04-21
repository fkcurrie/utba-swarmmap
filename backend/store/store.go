// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package store

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	"github.com/fkcurrie/utba-swarmmap/models"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Storer defines the interface for database and storage operations.
type Storer interface {
	GetAllSwarms(ctx context.Context) ([]models.SwarmReport, error)
	GetSwarmsBySessionID(ctx context.Context, sessionID string) ([]models.SwarmReport, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByVerificationToken(ctx context.Context, token string) (*models.User, error)
	GetUserByResetToken(ctx context.Context, token string) (*models.User, error)
	CreateUser(ctx context.Context, user models.User) (string, error)
	GetSession(ctx context.Context, sessionID string) (*models.Session, error)
	CreateSession(ctx context.Context, session models.Session) (string, error)
	DeleteSession(ctx context.Context, sessionID string) error
	CreateSwarm(ctx context.Context, swarm models.SwarmReport) error
	UpdateUser(ctx context.Context, userID string, updates []firestore.Update) error
	DeleteUser(ctx context.Context, userID string) error
	UpdateUserFields(ctx context.Context, userID string, fields map[string]interface{}) error
	DeleteSwarm(ctx context.Context, swarmID string) error
	UpdateSwarm(ctx context.Context, swarmID string, updates []firestore.Update) error
	GetAllUsers(ctx context.Context) ([]models.User, error)
	TrackVisit(ctx context.Context, visitorID string) error
	GetVisitCounts(ctx context.Context, days int) (map[string]int, error)
	UploadToGCS(ctx context.Context, swarmID string, file io.Reader, filename string) (string, error)
	// Add other methods here as we refactor handlers
}

// Store is the concrete implementation of the Storer interface using Firestore.
type Store struct {
	FirestoreClient FirestoreClient
	StorageClient   StorageClient
	BucketName      string
}

// NewStore creates a new Store.
func NewStore(fs *firestore.Client, sc *storage.Client, bucketName string) *Store {
	var fc FirestoreClient
	if fs != nil {
		fc = &FirestoreClientWrapper{Client: fs}
	}
	var stc StorageClient
	if sc != nil {
		stc = &StorageClientWrapper{Client: sc}
	}
	return &Store{
		FirestoreClient: fc,
		StorageClient:   stc,
		BucketName:      bucketName,
	}
}

const (
	reportsCollection  = "swarms"
	usersCollection    = "users"
	sessionsCollection = "sessions"
	visitsCollection   = "visits"
)

// TrackVisit records a unique visitor for the current day.
func (s *Store) TrackVisit(ctx context.Context, visitorID string) error {
	today := time.Now().UTC().Format("2006-01-02")
	docRef := s.FirestoreClient.Collection(visitsCollection).Doc(today)

	return s.FirestoreClient.RunTransaction(ctx, func(_ context.Context, tx Transaction) error {
		doc, err := tx.Get(docRef)
		if err != nil && status.Code(err) != codes.NotFound {
			return err
		}

		if !doc.Exists() {
			return tx.Set(docRef, map[string]interface{}{
				"visitors":  []string{visitorID},
				"timestamp": time.Now().UTC(),
			})
		}

		return tx.Update(docRef, []firestore.Update{
			{Path: "visitors", Value: firestore.ArrayUnion(visitorID)},
		})
	})
}

// GetVisitCounts retrieves the unique visit counts for the last n days.
func (s *Store) GetVisitCounts(ctx context.Context, days int) (map[string]int, error) {
	slog.Info("GetVisitCounts called", "days", days) // #nosec G706
	visitCounts := make(map[string]int)
	now := time.Now()
	startDate := now.AddDate(0, 0, -days)
	slog.Info("Querying visits", "startDate", startDate) // #nosec G706

	iter := s.FirestoreClient.Collection(visitsCollection).Where("timestamp", ">=", startDate).Documents(ctx)
	defer iter.Stop()

	docCount := 0
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			slog.Error("Error iterating visits", "error", err) // #nosec G706
			return nil, fmt.Errorf("failed to iterate visits: %v", err)
		}
		docCount++
		data := doc.Data()
		timestamp, ok := data["timestamp"].(time.Time)
		if !ok {
			slog.Warn("Skipping visit document with invalid timestamp", "docID", strings.ReplaceAll(strings.ReplaceAll(doc.ID(), "\n", ""), "\r", "")) // #nosec G706
			continue
		}
		dateStr := timestamp.Format("2006-01-02")
		visitors, ok := data["visitors"].([]interface{})
		if ok {
			visitCounts[dateStr] = len(visitors)
		} else {
			visitCounts[dateStr] = 0
		}
	}
	slog.Info("Found visit documents", "count", docCount) // #nosec G706

	// Ensure all days in the range are present in the map
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		if _, ok := visitCounts[date]; !ok {
			visitCounts[date] = 0
		}
	}

	slog.Info("Returning visit counts", "count", len(visitCounts)) // #nosec G706
	return visitCounts, nil
}

// GetUserByEmail finds a user by their email address.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	iter := s.FirestoreClient.Collection(usersCollection).Where("email", "==", email).Documents(ctx)
	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	var user models.User
	if err := doc.DataTo(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}
	user.ID = doc.ID()
	return &user, nil
}

// GetUserByVerificationToken finds a user by their verification token.
func (s *Store) GetUserByVerificationToken(ctx context.Context, token string) (*models.User, error) {
	iter := s.FirestoreClient.Collection(usersCollection).Where("verification_token", "==", token).Documents(ctx)
	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user by verification token: %w", err)
	}

	var user models.User
	if err := doc.DataTo(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}
	user.ID = doc.ID()
	return &user, nil
}

// GetUserByResetToken finds a user by their reset token.
func (s *Store) GetUserByResetToken(ctx context.Context, token string) (*models.User, error) {
	iter := s.FirestoreClient.Collection(usersCollection).Where("reset_token", "==", token).Documents(ctx)
	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user by reset token: %w", err)
	}

	var user models.User
	if err := doc.DataTo(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}
	user.ID = doc.ID()
	return &user, nil
}

// CreateUser creates a new user in Firestore.
func (s *Store) CreateUser(ctx context.Context, user models.User) (string, error) {
	userID := uuid.New().String()
	_, err := s.FirestoreClient.Collection(usersCollection).Doc(userID).Set(ctx, user)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}
	return userID, nil
}

// GetSession retrieves a session from Firestore.
func (s *Store) GetSession(ctx context.Context, sessionID string) (*models.Session, error) {
	doc, err := s.FirestoreClient.Collection(sessionsCollection).Doc(sessionID).Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("session not found in Firestore: %w", err)
	}

	var session models.Session
	if err := doc.DataTo(&session); err != nil {
		return nil, fmt.Errorf("failed to decode session: %w", err)
	}
	return &session, nil
}

// CreateSession creates a new session in Firestore.
func (s *Store) CreateSession(ctx context.Context, session models.Session) (string, error) {
	sessionID := uuid.New().String()
	if session.CSRFToken == "" {
		session.CSRFToken = uuid.New().String()
	}
	_, err := s.FirestoreClient.Collection(sessionsCollection).Doc(sessionID).Set(ctx, session)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	return sessionID, nil
}

// DeleteSession removes a session from Firestore.
func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := s.FirestoreClient.Collection(sessionsCollection).Doc(sessionID).Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session from Firestore: %w", err)
	}
	return nil
}

// CreateSwarm creates a new swarm report in Firestore.
func (s *Store) CreateSwarm(ctx context.Context, swarm models.SwarmReport) error {
	_, err := s.FirestoreClient.Collection(reportsCollection).Doc(swarm.ID).Set(ctx, swarm)
	if err != nil {
		return fmt.Errorf("failed to create swarm: %w", err)
	}
	return nil
}

// UpdateUser updates a user in Firestore.
func (s *Store) UpdateUser(ctx context.Context, userID string, updates []firestore.Update) error {
	_, err := s.FirestoreClient.Collection(usersCollection).Doc(userID).Update(ctx, updates)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// UpdateUserFields updates specific fields of a user in Firestore.
func (s *Store) UpdateUserFields(ctx context.Context, userID string, fields map[string]interface{}) error {
	var updates []firestore.Update
	for k, v := range fields {
		updates = append(updates, firestore.Update{
			Path:  k,
			Value: v,
		})
	}
	_, err := s.FirestoreClient.Collection(usersCollection).Doc(userID).Update(ctx, updates)
	if err != nil {
		return fmt.Errorf("failed to update user fields: %w", err)
	}
	return nil
}

// DeleteUser deletes a user from Firestore.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	_, err := s.FirestoreClient.Collection(usersCollection).Doc(userID).Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete user from Firestore: %w", err)
	}
	return nil
}

// DeleteSwarm deletes a swarm report from Firestore.
func (s *Store) DeleteSwarm(ctx context.Context, swarmID string) error {
	_, err := s.FirestoreClient.Collection(reportsCollection).Doc(swarmID).Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete swarm: %w", err)
	}
	return nil
}

// UpdateSwarm updates a swarm report in Firestore.
func (s *Store) UpdateSwarm(ctx context.Context, swarmID string, updates []firestore.Update) error {
	_, err := s.FirestoreClient.Collection(reportsCollection).Doc(swarmID).Update(ctx, updates)
	if err != nil {
		return fmt.Errorf("failed to update swarm: %w", err)
	}
	return nil
}

// GetAllUsers retrieves all users from Firestore.
func (s *Store) GetAllUsers(ctx context.Context) ([]models.User, error) {
	users := []models.User{}
	iter := s.FirestoreClient.Collection(usersCollection).Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate firestore documents: %w", err)
		}

		var user models.User
		if err := doc.DataTo(&user); err != nil {
			slog.Error("failed to convert firestore document to User", "error", err, "docID", strings.ReplaceAll(strings.ReplaceAll(doc.ID(), "\n", ""), "\r", "")) // #nosec G706
			continue
		}
		user.ID = doc.ID()
		users = append(users, user)
	}
	return users, nil
}

// GetAllSwarms retrieves all swarm reports from Firestore.
func (s *Store) GetAllSwarms(ctx context.Context) ([]models.SwarmReport, error) {
	reports := []models.SwarmReport{}
	iter := s.FirestoreClient.Collection(reportsCollection).Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate firestore documents: %w", err)
		}

		var report models.SwarmReport
		if err := doc.DataTo(&report); err != nil {
			slog.Error("failed to convert firestore document to SwarmReport", "error", err, "docID", strings.ReplaceAll(strings.ReplaceAll(doc.ID(), "\n", ""), "\r", "")) // #nosec G706
			continue
		}
		report.ID = doc.ID()
		reports = append(reports, report)
	}
	return reports, nil
}

// GetSwarmsBySessionID retrieves swarm reports for a specific session ID.
func (s *Store) GetSwarmsBySessionID(ctx context.Context, sessionID string) ([]models.SwarmReport, error) {
	reports := []models.SwarmReport{}
	iter := s.FirestoreClient.Collection(reportsCollection).Where("reporterSessionID", "==", sessionID).Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate firestore documents: %w", err)
		}

		var report models.SwarmReport
		if err := doc.DataTo(&report); err != nil {
			slog.Error("failed to convert firestore document to SwarmReport", "error", err, "docID", strings.ReplaceAll(strings.ReplaceAll(doc.ID(), "\n", ""), "\r", "")) // #nosec G706
			continue
		}
		report.ID = doc.ID()
		reports = append(reports, report)
	}
	return reports, nil
}

// UploadToGCS uploads a file to Google Cloud Storage.
func (s *Store) UploadToGCS(ctx context.Context, swarmID string, file io.Reader, filename string) (string, error) {
	ext := filepath.Ext(filename)
	uniqueFilename := fmt.Sprintf("%s/%s%s", swarmID, uuid.New().String(), ext)
	slog.Info("Uploading file to GCS", "filename", strings.ReplaceAll(strings.ReplaceAll(filename, "\n", ""), "\r", ""), "uniqueFilename", strings.ReplaceAll(strings.ReplaceAll(uniqueFilename, "\n", ""), "\r", "")) // #nosec G706

	obj := s.StorageClient.Bucket(s.BucketName).Object(uniqueFilename)
	writer := obj.NewWriter(ctx)

	// Set content type
	switch ext {
	case ".jpg", ".jpeg":
		writer.SetContentType("image/jpeg")
	case ".png":
		writer.SetContentType("image/png")
	case ".gif":
		writer.SetContentType("image/gif")
	case ".mp4":
		writer.SetContentType("video/mp4")
	case ".webm":
		writer.SetContentType("video/webm")
	case ".mov":
		writer.SetContentType("video/quicktime")
	case ".avi":
		writer.SetContentType("video/x-msvideo")
	case ".mpeg", ".mpg":
		writer.SetContentType("video/mpeg")
	case ".ogv":
		writer.SetContentType("video/ogg")
	case ".ts":
		writer.SetContentType("video/mp2t")
	case ".3gp":
		writer.SetContentType("video/3gpp")
	default:
		writer.SetContentType("application/octet-stream")
	}

	writer.SetACL([]storage.ACLRule{{Entity: storage.AllUsers, Role: storage.RoleReader}})

	if _, err := io.Copy(writer, file); err != nil {
		return "", fmt.Errorf("failed to copy file data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close writer: %w", err)
	}

	url := fmt.Sprintf("https://storage.googleapis.com/%s/%s", s.BucketName, uniqueFilename)
	slog.Info("Successfully uploaded to GCS", "filename", strings.ReplaceAll(strings.ReplaceAll(filename, "\n", ""), "\r", ""), "url", strings.ReplaceAll(strings.ReplaceAll(url, "\n", ""), "\r", "")) // #nosec G706
	return url, nil
}
