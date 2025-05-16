module github.com/fkcurrie/utba-swarmmap

go 1.22

require (
	cloud.google.com/go/firestore v1.18.0
)

// Transitive dependencies will be filled in by `go mod download` or `go mod tidy`
// during the build process in the container.
