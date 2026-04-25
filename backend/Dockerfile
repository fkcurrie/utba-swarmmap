# Copyright (c) 2026 Frank Currie (frank@sfle.ca)

# STAGE 1: Build the application
FROM golang:1.25.9-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

# STAGE 2: Create the final, minimal image
FROM alpine:3.21.3

# hadolint ignore=DL3018
RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=builder /app/server /app/server
COPY --from=builder /src/templates /app/templates/
# Copy static assets - they should be provided in the build context at backend/static
# We use wildcards to ensure the build succeeds even if assets are missing, 
# although they are required for full functionality.
COPY static* /app/static/

ENV PORT=8080
EXPOSE 8080
CMD ["/app/server"]
