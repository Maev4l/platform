BIN_DIR := bin

.PHONY: build run test lint clean

# Build the native binary (SPA must already be copied into internal/web/dist).
build:
	go build -ldflags="-s -w" -o $(BIN_DIR)/monitoring ./cmd

# Dev: fixed port so Vite's /api proxy (127.0.0.1:8080) matches. The built
# binary defaults to an auto-selected free port instead.
run:
	go run ./cmd --addr 127.0.0.1:8080

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR)
