dep:
	go mod download
test:
	go test
lint:
	golangci-lint run
