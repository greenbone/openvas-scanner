HAS_DOCKER_COMPOSE_V2 := $(shell docker compose version >/dev/null 2>&1 && echo 1)
HAS_DOCKER_COMPOSE_V1 := $(shell command -v docker-compose 2>/dev/null)

ifeq ($(HAS_DOCKER_COMPOSE_V2),1)
	# docker compose cannot deal with default veriables?
	CMD := docker compose
else ifneq ($(HAS_DOCKER_COMPOSE_V1),)
	CMD := docker-compose
else
	CMD := podman-compose
endif

TEST_ENVIRONMENTS := -f base.yaml -f mtls.yaml -f tests/victim.yaml

ifndef OPENVAS_IMAGE
	OPENVAS_IMAGE := ghcr.io/greenbone/openvas-scanner:stable
endif


all: openvasd-server.key client-certs/client1.pem

openvasd-server.key:
	cd ../rust/examples/tls/self-signed/ && make
	mv ../rust/examples/tls/self-signed/server.pem openvasd-server.pem
	mv ../rust/examples/tls/self-signed/server.rsa openvasd-server.key

client-certs/client1.pem:
	mkdir -p client-certs
	mkdir -p client-keys
	cd ../rust/examples/tls/self-signed/ && make
	mv ../rust/examples/tls/self-signed/server.pem client-certs/client1.pem
	mv ../rust/examples/tls/self-signed/server.rsa client-keys/client1.key

.PHONY: test-environment-down
test-environment-down:
	${CMD} ${TEST_ENVIRONMENTS} down -v

.PHONY: test-environment-logs
test-environment-logs:
	${CMD} ${TEST_ENVIRONMENTS} logs openvasd
	
	
.PHONY: test-environment-up
test-environment-up: openvasd-server.key client-certs/client1.pem
	OPENVAS_IMAGE=${OPENVAS_IMAGE} ${CMD} ${TEST_ENVIRONMENTS} up -d

.PHONY: local-test-environment-up
local-test-environment-up: openvasd-server.key client-certs/client1.pem
	cd .. && podman build -f .docker/prod.Dockerfile -t localhost/openvas:latest --build-arg BIN_VERSION=0.0.1 . 
	OPENVAS_IMAGE=localhost/openvas:latest ${CMD} ${TEST_ENVIRONMENTS} up

.PHONY: smoketests
smoketests: test-environment-up
	cd tests && make smoketests
