# Copyright (c) 2026 Frank Currie (frank@sfle.ca)

# STAGE 1: Build the minimal server
FROM golang:1.25.9-alpine3.21 AS builder

WORKDIR /app
COPY main.go .

# Build the static file server
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server main.go

# STAGE 2: Create the final image
FROM alpine:3.21.3

WORKDIR /app

# Copy the static assets
COPY static /app/static

# Copy the pre-built binary from the builder stage
COPY --from=builder /app/server /app/server

# Expose the port the app runs on
ENV PORT=8080
EXPOSE 8080

# Run the binary
CMD ["/app/server"]
