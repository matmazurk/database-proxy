.PHONY: build run certs up down

build:
	go build -o bin/database-proxy .

run: build
	./bin/database-proxy

certs:
	./certs/generate.sh

up: certs
	docker compose up --build

down:
	docker compose down -v
