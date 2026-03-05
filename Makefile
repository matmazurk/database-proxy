.PHONY: build run certs up up-oracle up-mysql test-oracle down

build:
	go build -o bin/database-proxy .

run: build
	./bin/database-proxy

certs:
	./certs/generate.sh

up: certs
	docker compose up --build

up-oracle: certs
	DB_TYPE=oracle DB_ADDR=oracle:2484 VAULT_DB_ROLE=oracle-readonly docker compose up --build

up-mysql: certs
	DB_TYPE=mysql DB_ADDR=mysql:3306 VAULT_DB_ROLE=mysql-readonly docker compose up --build

test-oracle: certs
	DB_TYPE=oracle DB_ADDR=oracle:2484 VAULT_DB_ROLE=oracle-readonly \
		docker compose --profile test up --build \
		--exit-code-from integration-test integration-test

down:
	docker compose down -v
