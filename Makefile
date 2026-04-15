.DEFAULT_GOAL := test

.PHONY: vendor lint test codecov run

vendor:
	@go mod vendor

lint: vendor
	@golangci-lint run ./...

test:
	@go test ./... -count=1 -race -coverprofile=coverage.txt -covermode=atomic

codecov: test
	@go tool cover -html=coverage.txt

run:
	@go run .
