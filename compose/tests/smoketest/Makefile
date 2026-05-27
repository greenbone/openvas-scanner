# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

MAKEFILE_PATH := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

ifndef OPENVASD_SERVER
	OPENVASD_SERVER := https://localhost:3000
endif

ifndef CLIENT_KEY
	CLIENT_KEY := ${MAKEFILE_PATH}/../../certs/clients/client1.key
endif

ifndef CLIENT_CERT
	CLIENT_CERT := ${MAKEFILE_PATH}/../../certs/clients/client1.pem
endif

ifndef HURL_BASE
	HURL_BASE := hurl -k \
							 --test \
							 --key ${CLIENT_KEY} \
							 --cert ${CLIENT_CERT} \
							 --variable server=${OPENVASD_SERVER} 
endif

# creates target for each scan definitions within scans-user-flows
SCANS_USER_FLOW := ${MAKEFILE_PATH}/scans-user-flows
SCANS_USER_FLOW := $(basename $(notdir $(wildcard $(SCANS_USER_FLOW)/*.json)))
SCANS_USER_FLOW := $(addprefix scans-user-flow-,$(SCANS_USER_FLOW))

CONTAINER_IMAGE_SCANNER_USER_FLOW := ${MAKEFILE_PATH}/container-image-scanner-user-flows
CONTAINER_IMAGE_SCANNER_USER_FLOW := $(basename $(notdir $(wildcard $(CONTAINER_IMAGE_SCANNER_USER_FLOW)/*.json)))
CONTAINER_IMAGE_SCANNER_USER_FLOW := $(addprefix container-image-scanner-user-flow-,$(CONTAINER_IMAGE_SCANNER_USER_FLOW))

OPENVAS_COMPAT_ROOT := ${MAKEFILE_PATH}/../../../rust/data/tests/scans
OPENVAS_COMPAT_CASES := $(notdir $(wildcard $(OPENVAS_COMPAT_ROOT)/scans/*))
OPENVAS_COMPAT_FLOW := $(addprefix openvas-compat-,$(OPENVAS_COMPAT_CASES))


all: up-and-running notus scans-user-flow-victim-simple-auth-ssh container-image-scanner-user-flow-local-registry-full

.PHONY: up-and-running
up-and-running:
	${HURL_BASE} ${MAKEFILE_PATH}/up-and-running/*.hurl

.PHONY: notus
notus:
	${HURL_BASE} ${MAKEFILE_PATH}/notus/*.hurl

.PHONY: scans
scans:
	${HURL_BASE} ${MAKEFILE_PATH}/scans/*.hurl

.PHONY: $(SCANS_USER_FLOW)
$(SCANS_USER_FLOW):
	$(eval SCAN_CONFIG := $(patsubst scans-user-flow-%,%,$@))
	${HURL_BASE} --variable scan_config=${SCAN_CONFIG}.json ${MAKEFILE_PATH}/scans-user-flows/*.hurl

.PHONY: $(CONTAINER_IMAGE_SCANNER_USER_FLOW)
$(CONTAINER_IMAGE_SCANNER_USER_FLOW):
	$(eval SCAN_CONFIG := $(patsubst container-image-scanner-user-flow-%,%,$@))
	${HURL_BASE} --variable scan_config=${SCAN_CONFIG}.json ${MAKEFILE_PATH}/container-image-scanner-user-flows/*.hurl

.PHONY: openvas-compat $(OPENVAS_COMPAT_FLOW)
openvas-compat: $(OPENVAS_COMPAT_FLOW)

$(OPENVAS_COMPAT_FLOW):
	$(eval OPENVAS_COMPAT_CASE := $(patsubst openvas-compat-%,%,$@))
	PREPARE_ONLY=1 START_ENVIRONMENT=0 \
		OPENVASD_SERVER=${OPENVASD_SERVER} \
		CLIENT_KEY=${CLIENT_KEY} \
		CLIENT_CERT=${CLIENT_CERT} \
		COMPOSE_FILE_ARGS="${COMPOSE_FILE_ARGS}" \
		$(OPENVAS_COMPAT_ROOT)/generate-openvas-snapshots.sh $(OPENVAS_COMPAT_CASE)
	configured_scan_id=$$(jq -r '.scan_id' "$(OPENVAS_COMPAT_ROOT)/scans/$(OPENVAS_COMPAT_CASE)/scan.json"); \
	curl -k --key ${CLIENT_KEY} --cert ${CLIENT_CERT} -fsS -o /dev/null -X DELETE "${OPENVASD_SERVER}/scans/$$configured_scan_id" || true
	expected_result_count=$$(jq -er '[.results[] | select(.type != "host_start" and .type != "host_end")] | length' "$(OPENVAS_COMPAT_ROOT)/snapshots/$(OPENVAS_COMPAT_CASE)/snapshot.json"); \
	${HURL_BASE} \
		--file-root $(OPENVAS_COMPAT_ROOT) \
		--variable scan_config=$(OPENVAS_COMPAT_ROOT)/scans/$(OPENVAS_COMPAT_CASE)/scan.json \
		--variable expected_result_count=$$expected_result_count \
		${MAKEFILE_PATH}/openvas-compat/*.hurl
