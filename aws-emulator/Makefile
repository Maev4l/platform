.PHONY: build update clean version

# Generic tag shared by every project on the machine: projects only choose their own
# container name, port and state folder when they run it.
IMAGE := aws-emulator
# Marks every build of the image (see Dockerfile), so replaced builds can be pruned
# without touching any other image.
LABEL := eu.isnan.aws-emulator=true

# Build the image from the latest AWS package.
# The image is ~1.4 GB and every rebuild re-tags it, which would leave the previous
# build behind as an untagged image. So the replaced image is removed right after the
# build, and any leftover untagged emulator build (e.g. one a container was still using
# last time) is pruned by label — no other image on the machine is touched.
# The build cache is pruned the same way: the install step of the previous build stays
# behind as a ~1.2 GB private cache record that no build will ever reuse (builds always
# run with --no-cache). The description filter matches only that step, so other
# projects' build cache is kept.
build:
	@old=$$(docker image inspect -f '{{.Id}}' $(IMAGE) 2>/dev/null); \
	docker build --pull --no-cache -t $(IMAGE) . || exit 1; \
	new=$$(docker image inspect -f '{{.Id}}' $(IMAGE)); \
	if [ -n "$$old" ] && [ "$$old" != "$$new" ]; then docker rmi "$$old" >/dev/null 2>&1 || true; fi; \
	docker image prune -f --filter label=$(LABEL) >/dev/null; \
	docker buildx prune -f --filter 'description~=aws-emulator\.rpm' >/dev/null

# Rebuild only when AWS has published a newer release than the installed image, so
# routine refreshes do not download and store 1.4 GB for nothing. Release tags are
# read from the public GitHub repository (release tags only: vX.Y.Z, no suffix).
update:
	@latest=$$(git ls-remote --tags --refs --sort=-v:refname https://github.com/aws/aws-emulator \
		| sed 's,.*refs/tags/,,' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1); \
	installed=$$(docker run --rm $(IMAGE) -v 2>/dev/null | awk '/^Version:/ {print "v" $$2}'); \
	if [ -z "$$latest" ]; then echo "Could not determine the latest AWS Emulator release"; exit 1; fi; \
	if [ "$$latest" = "$$installed" ]; then echo "AWS Emulator $$installed is up to date"; \
	else echo "Updating AWS Emulator $${installed:-(none)} -> $$latest"; $(MAKE) --no-print-directory build; fi

# Show the installed emulator version.
version:
	@docker run --rm $(IMAGE) -v

# Remove the image (and any leftover build of it) and its build cache.
clean:
	-docker rmi $(IMAGE)
	docker image prune -f --filter label=$(LABEL)
	docker buildx prune -f --filter 'description~=aws-emulator\.rpm'
