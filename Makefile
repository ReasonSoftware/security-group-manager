GO_BIN_DIR := $(GOPATH)/bin

test: lint
	@echo "unit testing..."
	@go test -v $$(go list ./... | grep -v vendor | grep -v mocks) -race -coverprofile=coverage.txt -covermode=atomic

GO_LINTER := $(GO_BIN_DIR)/golangci-lint
$(GO_LINTER):
	@echo "installing linter..."
	go get -u github.com/golangci/golangci-lint/cmd/golangci-lint

.PHONY: lint
lint: $(GO_LINTER)
	@echo "vendoring..."
	@go mod vendor
	@go mod tidy
	@echo "linting..."
	@golangci-lint run ./...

.PHONY: codecov
codecov: test
	@go tool cover -html=coverage.txt
