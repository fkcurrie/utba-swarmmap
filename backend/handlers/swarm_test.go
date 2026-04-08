// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

package handlers

import (
	"testing"
)

func TestValidateCoordinates(t *testing.T) {
	tests := []struct {
		name    string
		lat     string
		lon     string
		wantErr bool
	}{
		{"Valid coordinates", "43.6532", "-79.3832", false},
		{"Invalid latitude", "100.0", "-79.3832", true},
		{"Invalid longitude", "43.6532", "200.0", true},
		{"Non-numeric latitude", "abc", "-79.3832", true},
		{"Non-numeric longitude", "43.6532", "def", true},
		{"Empty latitude", "", "-79.3832", true},
		{"Boundary latitude North", "90.0", "0.0", false},
		{"Boundary latitude South", "-90.0", "0.0", false},
		{"Boundary longitude East", "0.0", "180.0", false},
		{"Boundary longitude West", "0.0", "-180.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := validateCoordinates(tt.lat, tt.lon)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCoordinates() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
