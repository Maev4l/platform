.PHONY: backend-deploy infra-plan infra-apply

NOTIFIER  := packages/notifier
RESPONDER := packages/responder
INFRA     := packages/infrastructure

# Full deploy: package both zips, then apply the infra.
backend-deploy:
	$(MAKE) -C $(NOTIFIER) package
	$(MAKE) -C $(RESPONDER) package
	$(MAKE) infra-apply

infra-plan:
	$(MAKE) -C $(NOTIFIER) package
	$(MAKE) -C $(RESPONDER) package
	terraform -chdir=$(INFRA) plan

infra-apply:
	terraform -chdir=$(INFRA) apply -auto-approve
