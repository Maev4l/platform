# Build settings for AWS Lambda (ARM64)
GOOS := linux
GOARCH := arm64
LDFLAGS := -s -w

.PHONY: build package lint format clean

BIN_DIR := bin
PACKAGE_DIR := dist

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/bootstrap ./cmd

package: build
	mkdir -p $(PACKAGE_DIR)
	cd $(BIN_DIR) && zip ../$(PACKAGE_DIR)/responder.zip bootstrap

lint:
	golangci-lint run ./...

format:
	golangci-lint fmt ./...

clean:
	rm -rf $(BIN_DIR)
