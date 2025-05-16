# Use an official Go runtime as a parent image for building
FROM golang:1.22-alpine as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod file
COPY go.mod ./

# Download dependencies (this will create go.sum if there are any)
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY main.go .
COPY templates/ templates/

# Build the Go app
# CGO_ENABLED=0 is for cross-compilation, GOOS=linux for Linux output
# -o /app/server makes the executable available at /app/server
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

# Use a minimal image for the final stage
FROM alpine:latest

# Copy the Pre-built binary file and templates from the previous stage
COPY --from=builder /app/server /app/server
COPY --from=builder /app/templates /app/templates/

# Set the Current Working Directory inside the container
WORKDIR /app

# Command to run the executable
CMD ["/app/server"] 