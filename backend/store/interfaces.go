package store

import (
	"context"
	"io"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
)

// Transaction is an interface for a Firestore transaction.
type Transaction interface {
	Get(dr DocumentRef) (DocumentSnapshot, error)
	Set(dr DocumentRef, data interface{}, opts ...firestore.SetOption) error
	Update(dr DocumentRef, updates []firestore.Update, opts ...firestore.Precondition) error
	Delete(dr DocumentRef, opts ...firestore.Precondition) error
}

// FirestoreClient is an interface for the Firestore client.
type FirestoreClient interface {
	Collection(path string) CollectionRef
	RunTransaction(ctx context.Context, f func(context.Context, Transaction) error, opts ...firestore.TransactionOption) error
	Close() error
}

// CollectionRef is an interface for a Firestore collection reference.
type CollectionRef interface {
	Doc(path string) DocumentRef
	Where(path, op string, value interface{}) Query
	Documents(ctx context.Context) DocumentIterator
}

// DocumentRef is an interface for a Firestore document reference.
type DocumentRef interface {
	Get(ctx context.Context) (DocumentSnapshot, error)
	Set(ctx context.Context, data interface{}, opts ...firestore.SetOption) (*firestore.WriteResult, error)
	Update(ctx context.Context, updates []firestore.Update, opts ...firestore.Precondition) (*firestore.WriteResult, error)
	Delete(ctx context.Context, opts ...firestore.Precondition) (*firestore.WriteResult, error)
	ID() string
}

// DocumentSnapshot is an interface for a Firestore document snapshot.
type DocumentSnapshot interface {
	Exists() bool
	DataTo(p interface{}) error
	Data() map[string]interface{}
	Ref() DocumentRef
	ID() string
}

// Query is an interface for a Firestore query.
type Query interface {
	Documents(ctx context.Context) DocumentIterator
}

// DocumentIterator is an interface for a Firestore document iterator.
type DocumentIterator interface {
	Next() (DocumentSnapshot, error)
	Stop()
}

// StorageClient is an interface for the Storage client.
type StorageClient interface {
	Bucket(name string) BucketHandle
	Close() error
}

// BucketHandle is an interface for a Storage bucket handle.
type BucketHandle interface {
	Object(name string) ObjectHandle
}

// ObjectHandle is an interface for a Storage object handle.
type ObjectHandle interface {
	NewWriter(ctx context.Context) ObjectWriter
}

// ObjectWriter is an interface for a Storage object writer.
type ObjectWriter interface {
	io.WriteCloser
	SetACL(rules []storage.ACLRule)
	SetContentType(contentType string)
}

// Wrappers for real clients

type FirestoreClientWrapper struct {
	Client *firestore.Client
}

func (w *FirestoreClientWrapper) Collection(path string) CollectionRef {
	return &CollectionRefWrapper{Coll: w.Client.Collection(path)}
}

func (w *FirestoreClientWrapper) RunTransaction(ctx context.Context, f func(context.Context, Transaction) error, opts ...firestore.TransactionOption) error {
	return w.Client.RunTransaction(ctx, func(c context.Context, tx *firestore.Transaction) error {
		return f(c, &TransactionWrapper{Tx: tx})
	}, opts...)
}

func (w *FirestoreClientWrapper) Close() error {
	return w.Client.Close()
}

type TransactionWrapper struct {
	Tx *firestore.Transaction
}

func (w *TransactionWrapper) Get(dr DocumentRef) (DocumentSnapshot, error) {
	snap, err := w.Tx.Get(dr.(*DocumentRefWrapper).Doc)
	if err != nil {
		return nil, err
	}
	return &DocumentSnapshotWrapper{Snap: snap}, nil
}

func (w *TransactionWrapper) Set(dr DocumentRef, data interface{}, opts ...firestore.SetOption) error {
	return w.Tx.Set(dr.(*DocumentRefWrapper).Doc, data, opts...)
}

func (w *TransactionWrapper) Update(dr DocumentRef, updates []firestore.Update, opts ...firestore.Precondition) error {
	return w.Tx.Update(dr.(*DocumentRefWrapper).Doc, updates, opts...)
}

func (w *TransactionWrapper) Delete(dr DocumentRef, opts ...firestore.Precondition) error {
	return w.Tx.Delete(dr.(*DocumentRefWrapper).Doc, opts...)
}

type CollectionRefWrapper struct {
	Coll *firestore.CollectionRef
}

func (w *CollectionRefWrapper) Doc(path string) DocumentRef {
	return &DocumentRefWrapper{Doc: w.Coll.Doc(path)}
}

func (w *CollectionRefWrapper) Where(path, op string, value interface{}) Query {
	return &QueryWrapper{Query: w.Coll.Where(path, op, value)}
}

func (w *CollectionRefWrapper) Documents(ctx context.Context) DocumentIterator {
	return &DocumentIteratorWrapper{Iter: w.Coll.Documents(ctx)}
}

type DocumentRefWrapper struct {
	Doc *firestore.DocumentRef
}

func (w *DocumentRefWrapper) Get(ctx context.Context) (DocumentSnapshot, error) {
	snap, err := w.Doc.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &DocumentSnapshotWrapper{Snap: snap}, nil
}

func (w *DocumentRefWrapper) Set(ctx context.Context, data interface{}, opts ...firestore.SetOption) (*firestore.WriteResult, error) {
	return w.Doc.Set(ctx, data, opts...)
}

func (w *DocumentRefWrapper) Update(ctx context.Context, updates []firestore.Update, opts ...firestore.Precondition) (*firestore.WriteResult, error) {
	return w.Doc.Update(ctx, updates, opts...)
}

func (w *DocumentRefWrapper) Delete(ctx context.Context, opts ...firestore.Precondition) (*firestore.WriteResult, error) {
	return w.Doc.Delete(ctx, opts...)
}

func (w *DocumentRefWrapper) ID() string {
	return w.Doc.ID
}

type DocumentSnapshotWrapper struct {
	Snap *firestore.DocumentSnapshot
}

func (w *DocumentSnapshotWrapper) Exists() bool {
	return w.Snap.Exists()
}

func (w *DocumentSnapshotWrapper) DataTo(p interface{}) error {
	return w.Snap.DataTo(p)
}

func (w *DocumentSnapshotWrapper) Data() map[string]interface{} {
	return w.Snap.Data()
}

func (w *DocumentSnapshotWrapper) Ref() DocumentRef {
	return &DocumentRefWrapper{Doc: w.Snap.Ref}
}

func (w *DocumentSnapshotWrapper) ID() string {
	return w.Snap.Ref.ID
}

type QueryWrapper struct {
	Query firestore.Query
}

func (w *QueryWrapper) Documents(ctx context.Context) DocumentIterator {
	return &DocumentIteratorWrapper{Iter: w.Query.Documents(ctx)}
}

type DocumentIteratorWrapper struct {
	Iter *firestore.DocumentIterator
}

func (w *DocumentIteratorWrapper) Next() (DocumentSnapshot, error) {
	snap, err := w.Iter.Next()
	if err != nil {
		return nil, err
	}
	return &DocumentSnapshotWrapper{Snap: snap}, nil
}

func (w *DocumentIteratorWrapper) Stop() {
	w.Iter.Stop()
}

type StorageClientWrapper struct {
	Client *storage.Client
}

func (w *StorageClientWrapper) Bucket(name string) BucketHandle {
	return &BucketHandleWrapper{Bucket: w.Client.Bucket(name)}
}

func (w *StorageClientWrapper) Close() error {
	return w.Client.Close()
}

type BucketHandleWrapper struct {
	Bucket *storage.BucketHandle
}

func (w *BucketHandleWrapper) Object(name string) ObjectHandle {
	return &ObjectHandleWrapper{Obj: w.Bucket.Object(name)}
}

type ObjectHandleWrapper struct {
	Obj *storage.ObjectHandle
}

func (w *ObjectHandleWrapper) NewWriter(ctx context.Context) ObjectWriter {
	return &ObjectWriterWrapper{Writer: w.Obj.NewWriter(ctx)}
}

type ObjectWriterWrapper struct {
	Writer *storage.Writer
}

func (w *ObjectWriterWrapper) Write(p []byte) (n int, err error) {
	return w.Writer.Write(p)
}

func (w *ObjectWriterWrapper) Close() error {
	return w.Writer.Close()
}

func (w *ObjectWriterWrapper) SetACL(rules []storage.ACLRule) {
	w.Writer.ACL = rules
}

func (w *ObjectWriterWrapper) SetContentType(contentType string) {
	w.Writer.ContentType = contentType
}
