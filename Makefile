.PHONY: integration-test
integration-test:
	@echo "Running integration tests..."
	@go test -v -tags=integration ./...