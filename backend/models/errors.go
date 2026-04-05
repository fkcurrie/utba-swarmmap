package models

import "errors"

var (
	// ErrSwarmNotFound is returned when a swarm report is not found.
	ErrSwarmNotFound = errors.New("swarm not found")
	// ErrUserNotFound is returned when a user is not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrSessionNotFound is returned when a session is not found.
	ErrSessionNotFound = errors.New("session not found")
	// ErrUnauthorized is returned when a user is not authorized to perform an action.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrInvalidInput is returned when the input provided is invalid.
	ErrInvalidInput = errors.New("invalid input")
)
