ADAPTER_VERSION := 1.0.0
BINARY := anchore-adapter
IMAGE_TAG := dev
IMAGE := anchore/harbor-scanner-adapter:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY):
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/anchore-adapter/main.go

container: build
	docker build --build-arg VERSION=$(ADAPTER_VERSION) -t $(IMAGE) .

test:
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go test ./...

clean:
	rm bin/$(BINARY)

container-clean:
	docker rmi $(IMAGE)
