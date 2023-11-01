COMMIT ?= $(shell git rev-parse HEAD)
SOURCES := $(shell find . -name '*.go')
BINARY := anchore-adapter
IMAGE_TAG ?= dev
IMAGE_REPOSITORY ?= anchore/harbor-scanner-adapter
IMAGE ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)
TEMPDIR = ./.tmp
DISTDIR = ./dist
SNAPSHOTDIR = ./snapshot

# Linting
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --timeout 5m --config .golangci.yaml
GOIMPORTS_CMD = $(TEMPDIR)/gosimports -local github.com/anchore

# ci dependency versions
GOLANG_CI_VERSION = v1.54.2
GOSIMPORTS_VERSION = v0.3.8
GORELEASER_VERSION = v1.16.1

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

.PHONY: bootstrap-go
bootstrap-go:
	$(call title,Boostrapping dependencies)
	go mod download

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR) $(RESULTSDIR)
	$(call title,Boostrapping tools)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ $(GOLANG_CI_VERSION)
	GOBIN="$(realpath $(TEMPDIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)
	GOBIN="$(realpath $(TEMPDIR))" go install github.com/goreleaser/goreleaser@$(GORELEASER_VERSION)

.PHONY: bootstrap
bootstrap: bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)

.PHONY: static-analysis
static-analysis: lint
	# Placeholder for future static analysis checks (this make target is used by CI)

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	$(LINTCMD) --fix
	go mod tidy

.PHONY: build
build:
	$(TEMPDIR)/goreleaser build --clean --snapshot

.PHONY: debug
debug: debug-build debug-run

.PHONY: debug-build
debug-build:
	docker build -f Dockerfile-dev -t anchore/harbor-scanner-adapter:debug .

.PHONY: debug-stop
debug-stop:
	kubectl delete -l app=harbor-scanner-anchore

.PHONY: debug-run
debug-run:
	kubectl apply -f ./k8s/harbor-adapter-anchore-debug.yaml
	kubectl port-forward $(shell kubectl get pods -o name | grep harbor-scanner-anchore) 2345:2345 8080:8080

.PHONY: debug-logs
debug-logs:
	kubectl logs -f $(shell kubectl get pods -o name | grep harbor-scanner-anchore)

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
