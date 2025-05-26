# Use an official Go runtime as a parent image for building
FROM golang:1.22-alpine as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Copy the source from the current directory to the Working Directory inside the container
COPY main.go .
COPY templates/ templates/
COPY static/ static/

# Fix any missing dependencies and update go.sum
RUN go mod tidy

# Download dependencies (this will create go.sum if there are any)
RUN go mod download

# Build the Go app
# CGO_ENABLED=0 is for cross-compilation, GOOS=linux for Linux output
# -o /app/server makes the executable available at /app/server
# -ldflags "-X main.version=$VERSION" sets the version variable
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=$VERSION" -o /app/server .

# Use a minimal image for the final stage
FROM alpine:latest

# Install timezone data
RUN apk add --no-cache tzdata

# Copy the Pre-built binary file and templates from the previous stage
COPY --from=builder /app/server /app/server
COPY --from=builder /app/templates /app/templates/
COPY --from=builder /app/static /app/static/

# Set the Current Working Directory inside the container
WORKDIR /app

# Set environment variables
ENV PORT=8080

# Command to run the executable
CMD ["/app/server"] 