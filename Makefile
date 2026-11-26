.PHONY: build test fmt clean

build:
	go build -trimpath -o bin/shipgate ./cmd/shipgate

test:
	go vet ./...
	go test ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin dist
