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

CURL := curl -vk --key ../client-keys/client1.key --cert ../client-certs/client1.pem 
CIS_ADDRESS := https://localhost:3000

$(CREATE_TARGETS):
	$(eval TARGET_NAME := $(patsubst create-%,%,$@))
	${CURL} -X POST -H "Content-Type: application/json" \
		--data-binary @$(SCAN_DIR)/$(TARGET_NAME).json \
		$(CIS_ADDRESS)/scans | sed 's/"//g' > $(STARTED_SCAN_DIR)/$(TARGET_NAME)


$(START_TARGETS):
	$(eval TARGET_NAME := $(patsubst start-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	${CURL} -d '{"action": "start"}' $(CIS_ADDRESS)/scans/$$ID

$(STOP_TARGETS):
	$(eval TARGET_NAME := $(patsubst stop-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	${CURL} -d '{"action": "stop"}' $(CIS_ADDRESS)/scans/$$ID

$(RM_TARGETS):
	$(eval TARGET_NAME := $(patsubst rm-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	${CURL} -X DELETE $(CIS_ADDRESS)/scans/$$ID && \
	rm $(STARTED_SCAN_DIR)/$(TARGET_NAME)

$(RESULTS_TARGETS):
	$(eval TARGET_NAME := $(patsubst results-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	${CURL} $(CIS_ADDRESS)/scans/$$ID/results | jq

$(STATUS_TARGETS):
	$(eval TARGET_NAME := $(patsubst status-%,%,$@))
	@ID=$$(cat $(STARTED_SCAN_DIR)/$(TARGET_NAME)) && \
	${CURL} $(CIS_ADDRESS)/scans/$$ID/status | jq

