#!/usr/bin/env bash

DOCKER_IMAGE = openvasd-test
CONTAINER_NAME = openvasd-test-container
PORT = 3000
API_KEY = changeme
PROFILE ?= release

.PHONY: build start-scanner openvas ospd-openvas clean status

build:
	@echo "Building openvasd locally in $(PROFILE) mode..."
	cd .. && cargo build --profile=$(PROFILE) --bin openvasd
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) -f Dockerfile ../..
	@echo "Build complete!"

start-scanner: build
	@echo "Starting openvasd with $(SCANNER_TYPE) backend..."
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run -d \
               --rm \
		--name $(CONTAINER_NAME) \
		-p $(PORT):3000 \
		-e SCANNER_TYPE=$(SCANNER_TYPE) \
		-e API_KEY=$(API_KEY) \
		-v "$(realpath ../target):/opt/openvasd_target" \
		-e PROFILE=$(PROFILE) \
		$(DOCKER_IMAGE)
	@echo "Container started. Waiting for service to be ready..."
	@for i in $$(seq 1 20); do \
		if curl -f -s -H "X-Api-Key: $(API_KEY)" http://localhost:$(PORT)/health/ready >/dev/null 2>&1; then \
			echo "openvasd ready"; \
			break; \
		fi; \
		if [ $$i -eq 20 ]; then \
			echo "Timeout: openvasd not ready after 10 seconds"; \
			exit 1; \
		fi; \
		sleep 0.5; \
	done

discovery:
	@echo "Running discovery scan..."
	/usr/bin/env bash ../examples/openvasd/start-discovery.sh

openvas:
	@$(MAKE) start-scanner SCANNER_TYPE=openvas

ospd:
	@$(MAKE) start-scanner SCANNER_TYPE=ospd

logs: 
	docker logs -f $(CONTAINER_NAME)

rebuild: clean build

shell:  build
	docker exec -it $(CONTAINER_NAME) /bin/bash

status: 
	@curl -v -s -H "X-Api-Key: $(API_KEY)" http://localhost:$(PORT)/health/ready

clean: 
	@echo "Stopping and removing container..."
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	@echo "Cleanup complete!"
