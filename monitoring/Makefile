.PHONY: run backend-build backend-run frontend-build frontend-serve \
        infra-plan infra-apply infra-output

INFRA := packages/infrastructure
APP    := packages/app
WEB    := packages/web

# One command to run the whole app: build the SPA, embed it, build the binary,
# then run it (serves the real UI on an auto-selected port and opens the browser).
# The SPA is baked into the binary, so the on-disk build artifacts are restored to
# a clean git tree right after building — the running binary still serves the UI.
# Loads packages/app/.env; log sources are auto-discovered from the Glue catalog
# at startup (no LOG_SOURCES needed — see CLAUDE.md).
run: backend-build
	@cd $(APP) && set -a; if [ -f .env ]; then . ./.env; fi; set +a; ./bin/monitoring

# Build the SPA, embed it into the Go module, build the binary.
# The SPA is baked into the binary by go:embed at compile time, so once the
# binary is built the on-disk build artifacts are restored to a clean git tree:
# the tracked dist/index.html placeholder is checked out (it's required so the
# Go module still compiles on a fresh checkout with no frontend build) and the
# gitignored dist/assets are removed. Keeps `backend-build` from dirtying the tree.
backend-build: frontend-build
	rm -rf $(APP)/internal/web/dist
	mkdir -p $(APP)/internal/web/dist
	cp -r $(WEB)/dist/. $(APP)/internal/web/dist/
	$(MAKE) -C $(APP) build
	@git checkout -- $(APP)/internal/web/dist/index.html 2>/dev/null || true
	@rm -rf $(APP)/internal/web/dist/assets

# Run locally (dev): triggers SSO login + serves API; pair with frontend-serve.
backend-run:
	$(MAKE) -C $(APP) run

frontend-build:
	yarn --cwd $(WEB) build

frontend-serve:
	yarn --cwd $(WEB) dev

infra-plan:
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve

infra-output:
	terraform -chdir=$(INFRA) output -json
