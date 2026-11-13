# AWS Emulator, packaged as a project-agnostic Docker image.
#
# AWS publishes no prebuilt image, and the emulator runs natively on Linux only, so on
# macOS (and in CI) it runs from this image, built off the official Linux package.
# Nothing in here is specific to one project: build it once as `aws-emulator` and any
# project on the machine can run it with its own container name, port and state folder.
#
#   make build     # or `make update` (rebuilds only when AWS published a new release)
#   docker run -d -p 127.0.0.1:9297:9297 -e EMULATOR_TELEMETRY=off \
#     -v "$PWD/.aws-emulator:/home/emulator/.aws/emulator" aws-emulator
#
# Mount the PARENT folder (/home/emulator/.aws/emulator), not the per-port folder: the
# emulator restricts the port folder to mode 700 at start, which fails on a Docker
# Desktop bind-mount root ("Operation not permitted").
#
# The package is deliberately NOT pinned: AWS ships security fixes and new API coverage
# only in the latest release, and improves the fidelity of each operation release by
# release. `make update` picks up a new release.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal
# Marks every build of this image, including replaced ones left untagged, so they can
# be pruned without touching any other image on the machine:
#   docker image prune -f --filter label=eu.isnan.aws-emulator=true
LABEL eu.isnan.aws-emulator="true"
ARG TARGETARCH
RUN case "$TARGETARCH" in arm64) a=aarch64 ;; amd64) a=x86_64 ;; *) exit 1 ;; esac \
    && curl -fsSLo /tmp/aws-emulator.rpm \
       "https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/latest/aws-emulator-$a.rpm" \
    && rpm -i /tmp/aws-emulator.rpm && rm /tmp/aws-emulator.rpm \
    && mkdir -p /home/emulator && chown 1000 /home/emulator
USER 1000
ENV HOME=/home/emulator
ENV PATH=/opt/aws-emulator/bin:$PATH
EXPOSE 9297
# Binding 0.0.0.0 is required for Docker port forwarding. Publish the port on the
# host's loopback only (-p 127.0.0.1:...), never on all interfaces.
ENTRYPOINT ["aws-emulator", "-b", "0.0.0.0"]
