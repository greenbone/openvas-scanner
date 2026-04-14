HAS_DOCKER_COMPOSE_V2 := $(shell docker compose version >/dev/null 2>&1 && echo 1)
HAS_DOCKER_COMPOSE_V1 := $(shell command -v docker-compose 2>/dev/null)

ifeq ($(HAS_DOCKER_COMPOSE_V2),1)
	CCMD := docker
	CMD := docker compose
else ifneq ($(HAS_DOCKER_COMPOSE_V1),)
	CMD := docker-compose
else
	CCMD := podman
	CMD := podman-compose
endif

TEST_ENVIRONMENTS := -f base.yaml -f mtls.yaml -f tests/victim.yaml -f local-registry.yaml

ifndef OPENVAS_IMAGE
	OPENVAS_IMAGE := ghcr.io/greenbone/openvas-scanner:stable
endif


all: certs/server.key certs/clients/client1.pem

certs/server.key:
	cd ../rust/examples/tls/self-signed/ && make
	mv ../rust/examples/tls/self-signed/server.pem certs/server.pem
	mv ../rust/examples/tls/self-signed/server.rsa certs/server.key

certs/clients/client1.pem:
	mkdir -p certs/clients
	cd ../rust/examples/tls/self-signed/ && make
	mv ../rust/examples/tls/self-signed/server.pem certs/clients/client1.pem
	mv ../rust/examples/tls/self-signed/server.rsa certs/clients/client1.key

.PHONY: test-environment-down
test-environment-down:
	${CMD} ${TEST_ENVIRONMENTS} down -v

.PHONY: test-environment-logs
test-environment-logs:
	${CMD} ${TEST_ENVIRONMENTS} logs

.PHONY: test-environment-up
test-environment-up: certs/server.key certs/clients/client1.pem
	OPENVAS_IMAGE=${OPENVAS_IMAGE} ${CMD} ${TEST_ENVIRONMENTS} up -d

.PHONY: local-test-environment-up
local-test-environment-up: certs/server.key certs/clients/client1.pem
	cd .. && podman build -f .docker/prod.Dockerfile -t localhost/openvas:latest --build-arg BIN_VERSION=0.0.1 . 
	OPENVAS_IMAGE=localhost/openvas:latest ${CMD} ${TEST_ENVIRONMENTS} up -d

define check_container_status
$(CCMD) ps -a --format '{{.Names}}' \
| grep '$(1)' \
| xargs $(CCMD) inspect -f '{{.State.Status}}' \
| grep -qx '$(2)'
endef

define wait_for_status
@printf "Waiting for $(1) to be $(2): "
while ! $(call check_container_status,$(1),$(2)); do \
	sleep 1; \
done
@printf "$(2)\n"
endef

.PHONY: wait-for-services
wait-for-services:
	@$(call wait_for_status,openvasd,running)
	@$(call wait_for_status,registry_seed,exited)

.PHONY: test-environment-up
test-environment-running: test-environment-up wait-for-services

.PHONY: local-test-environment-up
local-test-environment-running: local-test-environment-up wait-for-services

.PHONY: smoketests
smoketests: wait-for-images
	cd tests && make smoketests
