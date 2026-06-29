# Distroless static base: ships CA certificates and is RUN-free, so the image builds
# for both linux/amd64 and linux/arm64 via buildx with no QEMU emulation. The adapter is
# a static CGO_ENABLED=0 Go binary, so it needs nothing else at runtime.
FROM gcr.io/distroless/static-debian12

ARG COMMIT

LABEL "maintainer"="dev@anchore.com"
LABEL "commit"=${COMMIT}
LABEL "source"="https://github.com/anchore/harbor-scanner-adapter"

COPY anchore-adapter /app/anchore-adapter

ENTRYPOINT ["/app/anchore-adapter"]
