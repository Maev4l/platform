BIN_DIR := bin

.PHONY: build run test lint clean

# Build the native binary (SPA must already be copied into internal/web/dist).
build:
	go build -ldflags="-s -w" -o $(BIN_DIR)/monitoring ./cmd

# Dev: serves on 127.0.0.1:8080 (matches Vite's /api proxy). A later task adds
# the --addr flag + auto-port selection to the built binary.
run:
	go run ./cmd

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR)
