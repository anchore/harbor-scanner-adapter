COMMIT ?= $(shell git rev-parse HEAD)
SOURCES := $(shell find . -name '*.go')
BINARY := anchore-adapter
IMAGE_TAG ?= dev
IMAGE_REPOSITORY ?= anchore/harbor-scanner-adapter
IMAGE ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)
TEMPDIR = ./.tmp
GORELEASER_VERSION = v1.16.1
DISTDIR = ./dist
SNAPSHOTDIR = ./snapshot

ifndef TEMPDIR
        $(error TEMPDIR is not set)
endif

ifndef SNAPSHOTDIR
        $(error SNAPSHOTDIR is not set)
endif

ifndef DISTDIR
        $(error DISTDIR is not set)
endif

all: test build

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR) $(RESULTSDIR)
	$(call title,Boostrapping tools)
	GOBIN="$(realpath $(TEMPDIR))" go install github.com/goreleaser/goreleaser@$(GORELEASER_VERSION)

.PHONY: build
build:
	$(TEMPDIR)/goreleaser build --clean --snapshot

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
	IMAGE_REPOSITORY=$(IMAGE_REPOSITORY) $(TEMPDIR)/goreleaser release --clean

.PHONY: snapshot
snapshot:
	IMAGE_REPOSITORY=$(IMAGE_REPOSITORY) $(TEMPDIR)/goreleaser release --clean --snapshot
