package models

import "time"

// SwarmReport defines the structure for a swarm report (matches Firestore document)
type SwarmReport struct {
	ID                    string    `firestore:"-" json:"id"` // Firestore doc ID, not stored in doc fields
	Latitude              float64   `firestore:"latitude" json:"latitude"`
	Longitude             float64   `firestore:"longitude" json:"longitude"`
	Description           string    `firestore:"description" json:"description"`
	Status                string    `firestore:"status" json:"status"`
	ReportedTimestamp     time.Time `firestore:"reportedTimestamp" json:"reportedTimestamp"`
	VerificationTimestamp time.Time `firestore:"verificationTimestamp,omitempty" json:"verificationTimestamp,omitempty"`
	CapturedTimestamp     time.Time `firestore:"capturedTimestamp,omitempty" json:"capturedTimestamp,omitempty"`
	LastUpdatedTimestamp  time.Time `firestore:"lastUpdatedTimestamp" json:"lastUpdatedTimestamp"`
	ReportedMediaURLs     []string  `firestore:"reportedMediaURLs,omitempty" json:"reportedMediaURLs,omitempty"`
	CapturedMediaURLs     []string  `firestore:"capturedMediaURLs,omitempty" json:"capturedMediaURLs,omitempty"`
	BeekeeperNotes        string    `firestore:"beekeeperNotes,omitempty" json:"beekeeperNotes,omitempty"`
	DisplayStatus         string    `firestore:"-" json:"displayStatus,omitempty"` // Transient, for frontend logic
	NearestIntersection   string    `firestore:"nearestIntersection,omitempty" json:"nearestIntersection,omitempty"`
	AssignedCollectorID   string    `firestore:"assignedCollectorID,omitempty" json:"assignedCollectorID,omitempty"`
	// Contact information for public reporters
	ReporterName          string    `firestore:"reporterName,omitempty" json:"reporterName,omitempty"`
	ReporterEmail         string    `firestore:"reporterEmail,omitempty" json:"reporterEmail,omitempty"`
	ReporterPhone         string    `firestore:"reporterPhone,omitempty" json:"reporterPhone,omitempty"`
	ReporterSessionID     string    `firestore:"reporterSessionID,omitempty" json:"reporterSessionID,omitempty"` // To track public user's reports
}

// User defines the structure for swarm collectors and admins
type User struct {
	ID        string    `json:"id" firestore:"-"`
	Email     string    `json:"email" firestore:"email"`
	Phone     string    `json:"phone" firestore:"phone"`
	Name      string    `json:"name" firestore:"name"`
	Location  string    `json:"location" firestore:"location"`
	Role      string    `json:"role" firestore:"role"`         // "site_admin", "collector_admin", or "collector"
	Status    string    `json:"status" firestore:"status"`     // "pending" or "approved"
	CreatedAt time.Time `json:"created_at" firestore:"created_at"`
}

// Session defines user session structure
type Session struct {
	UserID    string    `json:"userID"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expiresAt"`
}
