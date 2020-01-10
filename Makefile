build:
	go build ./...
.PHONY: build

test:
	go test ./... -race -cover -count=1
.PHONY: test

verify:
	go vet ./...
	./scripts/verify-code-format.sh
.PHONY: verify
