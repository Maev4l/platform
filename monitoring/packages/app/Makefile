BIN_DIR := bin

.PHONY: build run test lint clean

# Build the native binary (SPA must already be copied into internal/web/dist).
build:
	go build -ldflags="-s -w" -o $(BIN_DIR)/monitoring ./cmd

# Dev: load .env (gitignored config) if present, fall back to the terraform
# log_sources_env output for LOG_SOURCES, then serve on the fixed port Vite's
# /api proxy expects (127.0.0.1:8080). The built binary (no --addr) auto-selects.
run:
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; \
	  if [ -z "$$LOG_SOURCES" ]; then export LOG_SOURCES=$$(terraform -chdir=../infrastructure output -raw log_sources_env 2>/dev/null); fi; \
	  go run ./cmd --addr 127.0.0.1:8080

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR)
