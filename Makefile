.PHONY: test test-cov generate swag

test:
	go test -v -race ./...

test-cov:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

generate:
	go generate ./...

swag:
	swag init -g cmd/api/main.go
