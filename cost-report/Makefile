.PHONY: build deploy invoke infra-plan infra-apply infra-output clean

FUNCTION := function
INFRA    := infrastructure

# Build the Lambda zip (delegates to the function Makefile).
build:
	$(MAKE) -C $(FUNCTION) package

# Full deploy: build the zip, then apply the infra.
deploy: build infra-apply

infra-plan:
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve

infra-output:
	terraform -chdir=$(INFRA) output -json

# Manually trigger the report (writes the Lambda response to stdout).
invoke:
	aws lambda invoke --function-name platform-cost-report --region eu-central-1 /dev/stdout

clean:
	$(MAKE) -C $(FUNCTION) clean
