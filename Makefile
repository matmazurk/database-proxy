.PHONY: build run

build:
	go build -o bin/database-proxy .

run: build
	./bin/database-proxy
