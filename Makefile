COMMIT ?= $(shell git rev-parse HEAD)
SOURCES := $(shell find . -name '*.go')
BINARY := anchore-adapter
IMAGE_TAG ?= dev
REPOSITORY ?= anchore/harbor-scanner-adapter
IMAGE ?= $(REPOSITORY):$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) cmd/anchore-adapter/main.go

.PHONY: container
container: build
	docker build --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

.PHONY: test
test:
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go test ./...

clean: clean-binary

.PHONY: clean-all
clean-all: clean-container clean-binary

.PHONY: clean-binary
clean-binary:
	rm $(BINARY)

.PHONY: clean-container
clean-container:
	docker rmi $(IMAGE)

.PHONY: push
push: container
	docker push $(IMAGE)
