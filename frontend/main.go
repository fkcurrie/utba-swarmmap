package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// getEnv reads an environment variable with a fallback value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	portStr := os.Getenv("PORT")
	if portStr == "" {
		portStr = "8080"
	}

	// Sanitize port to avoid log injection warning (CWE-117).
	// Validating that it is a number and then re-converting to string
	// is a strong way to ensure no malicious characters are present.
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		// If port is invalid, we fatal for clarity on configuration error.
		log.Fatalf("Invalid PORT environment variable: %v", err)
	}

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Printf("Listening on port %d", portInt)

	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(portInt),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
