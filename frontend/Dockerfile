# STAGE 1: Build the minimal server
FROM golang:1.22-alpine as builder

WORKDIR /app
COPY main.go .

# Build the static file server
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server main.go

# STAGE 2: Create the final image
FROM alpine:latest

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
