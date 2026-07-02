.PHONY: run backend-build backend-run frontend-build frontend-serve \
        install uninstall infra-plan infra-apply infra-output

INFRA := packages/infrastructure
APP    := packages/app
WEB    := packages/web

INSTALL_DIR := $(HOME)/.local/bin
INSTALL_LINK := $(INSTALL_DIR)/monitoring

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

# Symlink the built binary into $PATH so `monitoring` runs from anywhere.
# A link (not a copy) means every `backend-build` is picked up with no re-install.
# Uses an absolute target (abspath) so the link doesn't resolve relative to
# $(INSTALL_DIR). $(INSTALL_DIR) is user-writable (~/.local/bin) — no sudo needed;
# ensure it's on your PATH.
# NOTE: the installed binary doesn't source packages/app/.env (that's `make run`);
# provide MONITORING_* / GEOIP_* config via your shell environment.
install: backend-build
	mkdir -p $(INSTALL_DIR)
	ln -sf $(abspath $(APP)/bin/monitoring) $(INSTALL_LINK)
	@echo "Linked $(INSTALL_LINK) -> $(abspath $(APP)/bin/monitoring)"

uninstall:
	rm -f $(INSTALL_LINK)
	@echo "Removed $(INSTALL_LINK)"

infra-plan:
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve

infra-output:
	terraform -chdir=$(INFRA) output -json
