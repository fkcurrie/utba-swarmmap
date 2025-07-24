package store

import (
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
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
	CreateUser(ctx context.Context, user models.User) (string, error)
	GetSession(ctx context.Context, sessionID string) (*models.Session, error)
	CreateSession(ctx context.Context, session models.Session) (string, error)
	DeleteSession(ctx context.Context, sessionID string) error
	CreateSwarm(ctx context.Context, swarm models.SwarmReport) error
	UpdateUser(ctx context.Context, userID string, updates []firestore.Update) error
	DeleteUser(ctx context.Context, userID string) error
	DeleteSwarm(ctx context.Context, swarmID string) error
	UpdateSwarm(ctx context.Context, swarmID string, updates []firestore.Update) error
	GetAllUsers(ctx context.Context) ([]models.User, error)
	TrackVisit(ctx context.Context, visitorID string) error
	GetVisitCounts(ctx context.Context, days int) (map[string]int, error)
	// Add other methods here as we refactor handlers
}

// Store is the concrete implementation of the Storer interface using Firestore.
type Store struct {
	FirestoreClient *firestore.Client
	StorageClient   *storage.Client
	BucketName      string
}

// NewStore creates a new Store.
func NewStore(fs *firestore.Client, sc *storage.Client, bucketName string) *Store {
	return &Store{
		FirestoreClient: fs,
		StorageClient:   sc,
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

	return s.FirestoreClient.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		doc, err := tx.Get(docRef)
		if err != nil && status.Code(err) != codes.NotFound {
			return err
		}

		if !doc.Exists() {
			return tx.Set(docRef, map[string]interface{}{
				"visitors": []string{visitorID},
			})
		}

		return tx.Update(docRef, []firestore.Update{
			{Path: "visitors", Value: firestore.ArrayUnion(visitorID)},
		})
	})
}

// GetVisitCounts retrieves the unique visit counts for the last n days.
func (s *Store) GetVisitCounts(ctx context.Context, days int) (map[string]int, error) {
	log.Printf("GetVisitCounts called for the last %d days", days)
	visitCounts := make(map[string]int)
	now := time.Now()
	startDate := now.AddDate(0, 0, -days)
	log.Printf("Querying visits from %v", startDate)

	iter := s.FirestoreClient.Collection(visitsCollection).Where("timestamp", ">=", startDate).Documents(ctx)
	defer iter.Stop()

	docCount := 0
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("Error iterating visits: %v", err)
			return nil, fmt.Errorf("failed to iterate visits: %v", err)
		}
		docCount++
		timestamp, ok := doc.Data()["timestamp"].(time.Time)
		if !ok {
			log.Printf("Skipping visit document with invalid timestamp: %s", doc.Ref.ID)
			continue
		}
		dateStr := timestamp.Format("2006-01-02")
		visitCounts[dateStr]++
	}
	log.Printf("Found %d visit documents in the date range.", docCount)

	// Ensure all days in the range are present in the map
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		if _, ok := visitCounts[date]; !ok {
			visitCounts[date] = 0
		}
	}

	log.Printf("Returning visit counts: %v", visitCounts)
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
	user.ID = doc.Ref.ID
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
	_, err := s.FirestoreClient.Collection(sessionsCollection).Doc(sessionID).Set(ctx, session)
	if err != nil {
		return "", fmt.Errorf("failed to create session in Firestore: %w", err)
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

// DeleteUser deletes a user from Firestore.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	_, err := s.FirestoreClient.Collection(usersCollection).Doc(userID).Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
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
	var users []models.User
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
			log.Printf("failed to convert firestore document to User: %v", err)
			continue
		}
		user.ID = doc.Ref.ID
		users = append(users, user)
	}
	return users, nil
}

// GetAllSwarms retrieves all swarm reports from Firestore.
func (s *Store) GetAllSwarms(ctx context.Context) ([]models.SwarmReport, error) {
	var reports []models.SwarmReport
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
			log.Printf("failed to convert firestore document to SwarmReport: %v", err)
			continue
		}
		report.ID = doc.Ref.ID
		reports = append(reports, report)
	}
	return reports, nil
}


// GetSwarmsBySessionID retrieves swarm reports for a specific session ID.
func (s *Store) GetSwarmsBySessionID(ctx context.Context, sessionID string) ([]models.SwarmReport, error) {
	var reports []models.SwarmReport
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
			log.Printf("failed to convert firestore document to SwarmReport: %v", err)
			continue
		}
		report.ID = doc.Ref.ID
		reports = append(reports, report)
	}
	return reports, nil
}

// UploadToGCS uploads a file to Google Cloud Storage.
func (s *Store) UploadToGCS(ctx context.Context, swarmID string, file io.Reader, filename string) (string, error) {
	ext := filepath.Ext(filename)
	uniqueFilename := fmt.Sprintf("%s/%s%s", swarmID, uuid.New().String(), ext)
	log.Printf("Uploading file %s to GCS as %s", filename, uniqueFilename)

	obj := s.StorageClient.Bucket(s.BucketName).Object(uniqueFilename)
	writer := obj.NewWriter(ctx)

	// Set content type
	switch ext {
	case ".jpg", ".jpeg":
		writer.ContentType = "image/jpeg"
	case ".png":
		writer.ContentType = "image/png"
	// Add other content types as needed
	default:
		writer.ContentType = "application/octet-stream"
	}

	writer.ACL = []storage.ACLRule{{Entity: storage.AllUsers, Role: storage.RoleReader}}

	if _, err := io.Copy(writer, file); err != nil {
		return "", fmt.Errorf("failed to copy file data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close writer: %w", err)
	}

	url := fmt.Sprintf("https://storage.googleapis.com/%s/%s", s.BucketName, uniqueFilename)
	log.Printf("Successfully uploaded %s to %s", filename, url)
	return url, nil
}
