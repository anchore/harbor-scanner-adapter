COMMIT ?= $(shell git rev-parse HEAD)
SOURCES := $(shell find . -name '*.go')
BINARY := anchore-adapter
IMAGE_TAG ?= dev
IMAGE_REPOSITORY ?= anchore/harbor-scanner-adapter
IMAGE ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)

all: test build

.PHONY: build
build:
	goreleaser build --clean --snapshot

.PHONY: test
test:
	CGO_ENABLED=0 go test ./...

.PHONY: clean
clean: clean-binary clean-image

.PHONY: clean-binary
clean-binary:
	rm -f $(BINARY)
	rm -rf dist/

.PHONY: clean-image
clean-image:
	docker rmi -f $(IMAGE)

.PHONY: release
release: 
	IMAGE_REPOSITORY=$(IMAGE_REPOSITORY) goreleaser release --clean --skip-publish --skip-validate

.PHONY: snapshot
snapshot:
	IMAGE_REPOSITORY=$(IMAGE_REPOSITORY) goreleaser release --clean --snapshot
