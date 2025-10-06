#!/usr/bin/env bash

DOCKER_IMAGE = openvasd-test
TARGET_IMAGE = openvasd-target
CONTAINER_NAME = openvasd-test-container
TARGET_CONTAINER_NAME = openvasd-target-container
PORT = 3000
API_KEY = changeme
PROFILE ?= release

.PHONY: build start-scanner openvas ospd-openvas clean status build-target start-target stop-target target-ip scan-discovery scan-status scan-results

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
	@echo "Stopping and removing containers..."
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm -f $(TARGET_CONTAINER_NAME) 2>/dev/null || true

build-target:
	@echo "Building target container..."
	docker build -t $(TARGET_IMAGE) -f Dockerfile.target .

start-target: build-target
	@echo "Starting target container..."
	@docker rm -f $(TARGET_CONTAINER_NAME) 2>/dev/null || true
	docker run -d \
		--rm \
		--name $(TARGET_CONTAINER_NAME) \
		$(TARGET_IMAGE)

stop-target:
	@docker rm -f $(TARGET_CONTAINER_NAME) 2>/dev/null || true

target-ip:
	@docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(TARGET_CONTAINER_NAME)

scan-discovery:
	@echo "Starting discovery scan against target..."
	@# Check if scanner is running
	@if ! curl -f -s -H "X-Api-Key: $(API_KEY)" http://localhost:$(PORT)/health/ready >/dev/null 2>&1; then \
		echo "Error: Scanner not running. Start it first with:"; \
		echo "  make openvas  (for OpenVAS backend)"; \
		echo "  make ospd     (for OSPD backend)"; \
		exit 1; \
	fi
	@# Ensure target container is running
	@TARGET_IP=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(TARGET_CONTAINER_NAME) 2>/dev/null); \
	if [ -z "$$TARGET_IP" ]; then \
		echo "Target container not running, starting it..."; \
		$(MAKE) start-target; \
		TARGET_IP=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(TARGET_CONTAINER_NAME)); \
	fi; \
	echo "Target IP: $$TARGET_IP"; \
	echo "Waiting for target container to be ready..."; \
	sleep 3; \
	SCAN_ID=$$(curl -s -H "Content-Type: application/json" -H "X-Api-Key: $(API_KEY)" \
		-d '{"target":{"hosts":["'$$TARGET_IP'"],"ports":[{"protocol":"tcp","range":[{"start":1,"end":1000}]}]},"vts":[]}' \
		http://localhost:$(PORT)/scans | sed 's/"//g'); \
	echo "Scan ID: $$SCAN_ID"; \
	curl --fail-with-body -s -H "Content-Type: application/json" -H "X-Api-Key: $(API_KEY)" \
		-d '{"action": "start"}' "http://localhost:$(PORT)/scans/$$SCAN_ID" && \
	echo "Scan started. Use 'make scan-status SCAN_ID=$$SCAN_ID' to check status" && \
	echo "Export SCAN_ID=$$SCAN_ID"

scan-status:
	@if [ -z "$(SCAN_ID)" ]; then echo "Error: SCAN_ID not set. Use: make scan-status SCAN_ID=<id>"; exit 1; fi
	@curl --fail-with-body -H "X-Api-Key: $(API_KEY)" "http://localhost:$(PORT)/scans/$(SCAN_ID)/status"

scan-results:
	@if [ -z "$(SCAN_ID)" ]; then echo "Error: SCAN_ID not set. Use: make scan-results SCAN_ID=<id>"; exit 1; fi
	@curl --fail-with-body -H "X-Api-Key: $(API_KEY)" "http://localhost:$(PORT)/scans/$(SCAN_ID)/results"
