.PHONY: test
test:
	@echo "Running tests..."
	@go test -v -tags=unit,integration_test -coverprofile=coverage.out -coverpkg=./... -cover ./...