# Go application name
APP_NAME = katello
DESTDIR ?= /

# Go source files
SRC = katello.go

# Default target when running `make` without arguments
default: build

GOPATH ?= $(shell go env GOPATH)
ifeq ($(GOPATH),)
    GOPATH := /tmp/go
endif
export GOPATH

# Install dependencies
deps:
	@echo "Fetching dependencies..."
	go mod tidy

# Build the Go application
build: deps
	@echo "Building application..."
	go build -o $(APP_NAME) .

# Install the application
install: build
	@echo "Installing $(APP_NAME) to $(DESTDIR)/usr/lib/apt/methods/"
	install -d $(DESTDIR)/usr/lib/apt/methods/
	install -m 755 $(APP_NAME) $(DESTDIR)/usr/lib/apt/methods/

.PHONY: deps build install

# Run the application
run: build
	./$(APP_NAME)

# Clean build files
clean:
	rm -f $(APP_NAME)

# Format Go code
fmt:
	go fmt $(SRC)

# Lint the code (optional, if `golangci-lint` is installed)
lint:
	golangci-lint run

# Display help
help:
	@echo "Makefile Commands:"
	@echo "  make build    - Compile the Go application"
	@echo "  make install  - Install the Go application"
	@echo "  make run      - Build and run the application"
	@echo "  make clean    - Remove the compiled binary"
	@echo "  make fmt      - Format the Go source code"
	@echo "  make lint     - Run static code analysis (requires golangci-lint)"
	@echo "  make deps     - Install dependencies (if required)"

.PHONY: build run clean fmt lint help deps

