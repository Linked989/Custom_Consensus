APP=./cmd/node

# Defaults (override: make run-seed BIND=10.110.11.137)
BIND?=127.0.0.1
SEED_PORT?=4001
SWARM?=swarm.key

.PHONY: build run-seed run-peer gen-swarm fmt tidy

build:
	go build $(APP)

run-seed:
	go run $(APP) -bind $(BIND) -port $(SEED_PORT) -pnet $(SWARM) -mdns=true -dev-gen-tx -produce-blocks -block-interval=2s -stats=2s

run-peer:
	go run $(APP) -bind $(BIND) -port 0 -pnet $(SWARM) -mdns=true -stats=2s

gen-swarm:
	go run $(APP) -gen-swarm-key $(SWARM)

fmt:
	go fmt ./...

tidy:
	go mod tidy

