# Go application name
APP_NAME = katello

# Go source files
SRC = katello.go

# Install dependencies
deps:
	go mod tidy
	go get gopkg.in/ini.v1

# Build the Go application
build: deps
	go build -o $(APP_NAME) $(SRC)

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
	@echo "  make run      - Build and run the application"
	@echo "  make clean    - Remove the compiled binary"
	@echo "  make fmt      - Format the Go source code"
	@echo "  make lint     - Run static code analysis (requires golangci-lint)"
	@echo "  make deps     - Install dependencies (if required)"

.PHONY: build run clean fmt lint help deps

