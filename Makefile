.PHONY: build run certs up up-oracle down

build:
	go build -o bin/database-proxy .

run: build
	./bin/database-proxy

certs:
	./certs/generate.sh

up: certs
	docker compose up --build

up-oracle: certs
	DB_TYPE=oracle DB_ADDR=oracle:1521 VAULT_DB_ROLE=oracle-readonly docker compose up --build

down:
	docker compose down -v
