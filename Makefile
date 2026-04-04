.PHONY: all build clean test

all: build

build:
	@echo "Building backend..."
	cd backend && go build -o backend_bin .
	@echo "Building frontend..."
	cd frontend && go build -o frontend_bin main.go

clean:
	@echo "Cleaning up..."
	rm -f backend/backend_bin
	rm -f frontend/frontend_bin

test:
	@echo "Testing backend..."
	cd backend && go test ./...
