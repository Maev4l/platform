.PHONY: backend-build backend-run frontend-build frontend-serve \
        infra-plan infra-apply infra-output

INFRA := packages/infrastructure
APP    := packages/app
WEB    := packages/web

# Build the SPA, embed it into the Go module, build the binary.
backend-build: frontend-build
	rm -rf $(APP)/internal/web/dist
	mkdir -p $(APP)/internal/web/dist
	cp -r $(WEB)/dist/. $(APP)/internal/web/dist/
	$(MAKE) -C $(APP) build

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
