BASE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.DEFAULT_GOAL := start


SCAN_DIR := scans
STARTED_SCAN_DIR := known-scans

JSON_FILES := $(wildcard $(SCAN_DIR)/*.json)

BASE_NAMES := $(basename $(notdir $(JSON_FILES)))
CREATE_TARGETS :=  $(addprefix create-,$(BASE_NAMES))

CREATED_SCANS := $(wildcard $(STARTED_SCAN_DIR)/*)
SCANS_BASE_NAMES := $(basename $(notdir $(CREATED_SCANS)))

START_TARGETS := $(addprefix start-,$(SCANS_BASE_NAMES))
STOP_TARGETS := $(addprefix stop-,$(SCANS_BASE_NAMES))
RM_TARGETS := $(addprefix rm-,$(SCANS_BASE_NAMES))
RESULTS_TARGETS := $(addprefix results-,$(SCANS_BASE_NAMES))
STATUS_TARGETS := $(addprefix status-,$(SCANS_BASE_NAMES))

STARTED_SCANS := $(wildcard $(STARTED_SCAN_DIR)/*)

START_SCANS := $(basename $(notdir $(JSON_FILES)))

CIS_ADDRESS := http://localhost:3000/container-image-scanner/

.PHONY: stop-notus start-notus rm-notus stop-local-registry start-local-registry rm-local-registry \
        $(CREATE_TARGETS) $(START_TARGETS) $(STOP_TARGETS) $(RM_TARGETS) $(RESULTS_TARGETS) $(STATUS_TARGETS) \
        start stop rm



stop-notus:
	@cd ${BASE_PATH}/notus/; make stop

start-notus:
	@cd ${BASE_PATH}/notus/; make start

rm-notus:
	@cd ${BASE_PATH}/notus/; make rm

stop-local-registry:
	@cd ${BASE_PATH}/local-registry/; make stop

start-local-registry:
	@cd ${BASE_PATH}/local-registry/; make start-mirror

rm-local-registry:
	@cd ${BASE_PATH}/local-registry/; make rm

$(CREATE_TARGETS):
	$(eval TARGET_NAME := $(patsubst create-%,%,$@))
	@ curl -s -X POST -H "Content-Type: application/json" \
		--data-binary @$(SCAN_DIR)/$(TARGET_NAME).json \
		$(CIS_ADDRESS)/scans | sed 's/"//g' > $(STARTED_SCAN_DIR)/$(TARGET_NAME)


$(START_TARGETS):
	$(eval TARGET_NAME := $(patsubst start-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	curl -s -d '{"action": "start"}' $(CIS_ADDRESS)/scans/$$ID

$(STOP_TARGETS):
	$(eval TARGET_NAME := $(patsubst stop-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	curl -s -d '{"action": "stop"}' $(CIS_ADDRESS)/scans/$$ID

$(RM_TARGETS):
	$(eval TARGET_NAME := $(patsubst rm-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	curl -s -X DELETE $(CIS_ADDRESS)/scans/$$ID && \
	rm $(STARTED_SCAN_DIR)/$(TARGET_NAME)

$(RESULTS_TARGETS):
	$(eval TARGET_NAME := $(patsubst results-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	curl -s $(CIS_ADDRESS)/scans/$$ID/results | jq

$(STATUS_TARGETS):
	$(eval TARGET_NAME := $(patsubst status-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	curl -s $(CIS_ADDRESS)/scans/$$ID/status | jq

../../target/release/openvasd:
	@cargo build --release > /dev/null 2>&1

container-image-scanner.pid: ../../target/release/openvasd 
	@sh ./start-container-image-scanner.sh

.PHONY: start-container-image-scanner
start-container-image-scanner: container-image-scanner.pid

stop-container-image-scanner:
	@kill $$(cat container-image-scanner.pid 2> /dev/null) > /dev/null 2>&1 || true 
	@rm -f container-image-scanner.pid

rm-container-image-scanner: stop-container-image-scanner
	@rm -f ../../target/release/openvasd
	@rm -f container-image-scanner.log
	@rm -f example.db
	@rm -f example.db-shm
	@rm -f example.db-wal


stop: stop-notus stop-local-registry stop-container-image-scanner

start: start-notus start-local-registry start-container-image-scanner

rm: rm-notus rm-local-registry rm-container-image-scanner
