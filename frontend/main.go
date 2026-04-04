package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

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
		// If port is invalid, we fallback to 8080 or fatal out.
		// Since this is a simple frontend, we'll fatal for clarity on configuration error.
		log.Fatalf("Invalid PORT environment variable: %v", err)
	}
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Printf("Listening on port %d", portInt)
	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(portInt),
		Handler:      nil,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
