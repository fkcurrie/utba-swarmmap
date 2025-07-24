# STAGE 1: Build the application
FROM golang:1.22-alpine as builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

# STAGE 2: Create the final, minimal image
FROM alpine:latest

RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=builder /app/server /app/server
COPY --from=builder /src/templates /app/templates/

ENV PORT=8080
EXPOSE 8080
CMD ["/app/server"]
 