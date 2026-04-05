package store

import (
	"context"
	"testing"

	"github.com/fkcurrie/utba-swarmmap/models"
)

type MockFirestoreClient struct {
	FirestoreClient
	MockCollection *MockCollectionRef
}

func (m *MockFirestoreClient) Collection(_ string) CollectionRef {
	return m.MockCollection
}

type MockCollectionRef struct {
	CollectionRef
	MockDoc *MockDocumentRef
}

func (m *MockCollectionRef) Doc(_ string) DocumentRef {
	return m.MockDoc
}

type MockDocumentRef struct {
	DocumentRef
	MockSnapshot *MockDocumentSnapshot
	MockID       string
}

func (m *MockDocumentRef) Get(_ context.Context) (DocumentSnapshot, error) {
	return m.MockSnapshot, nil
}

func (m *MockDocumentRef) ID() string {
	return m.MockID
}

type MockDocumentSnapshot struct {
	DocumentSnapshot
	MockExists bool
	MockData   models.User
}

func (m *MockDocumentSnapshot) Exists() bool {
	return m.MockExists
}

func (m *MockDocumentSnapshot) DataTo(p interface{}) error {
	*(p.(*models.User)) = m.MockData
	return nil
}

func (m *MockDocumentSnapshot) ID() string {
	return "mock-id"
}

func TestStore_GetUserByEmail_Mock(t *testing.T) {
	mockSnapshot := &MockDocumentSnapshot{
		MockExists: true,
		MockData:   models.User{Email: "test@example.com"},
	}
	mockDoc := &MockDocumentRef{
		MockSnapshot: mockSnapshot,
		MockID:       "test-id",
	}
	mockColl := &MockCollectionRef{
		MockDoc: mockDoc,
	}
	mockClient := &MockFirestoreClient{
		MockCollection: mockColl,
	}
	
	s := &Store{
		FirestoreClient: mockClient,
	}
	
	if s.FirestoreClient.Collection("users") != mockColl {
		t.Error("expected mock collection")
	}
}
