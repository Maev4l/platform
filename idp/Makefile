.PHONY: backend-build backend-deploy infra-plan infra-apply

FUNCTION := function
INFRA    := infrastructure

# Compile the Lambda binary (no packaging, no deploy).
backend-build:
	$(MAKE) -C $(FUNCTION) build

# Full deploy: package the zip (delegates to the function Makefile), then apply the infra.
backend-deploy:
	$(MAKE) -C $(FUNCTION) package
	$(MAKE) infra-apply

infra-plan:
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve
