# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

MAKEFILE_PATH := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

ifndef OPENVASD_SERVER
	OPENVASD_SERVER := https://localhost:3000
endif

ifndef CLIENT_KEY
	CLIENT_KEY := ${MAKEFILE_PATH}/../../client-keys/client1.key
endif

ifndef CLIENT_CERT
	CLIENT_CERT := ${MAKEFILE_PATH}/../../client-certs/client1.pem
endif

ifndef HURL_BASE
	HURL_BASE := hurl -vk \
							 --http2 \
							 --key ${CLIENT_KEY} \
							 --cert ${CLIENT_CERT} \
							 --variable server=${OPENVASD_SERVER} 
endif

# creates target for each scan definitions within scans-user-flows
SCANS_USER_FLOW := ${MAKEFILE_PATH}/scans-user-flows
SCANS_USER_FLOW := $(basename $(notdir $(wildcard $(SCANS_USER_FLOW)/*.json)))
SCANS_USER_FLOW := $(addprefix scans-user-flow-,$(SCANS_USER_FLOW))

all: up-and-running notus scans-user-flow-victim-simple-auth-ssh

.PHONY: up-and-running
up-and-running:
	${HURL_BASE} ${MAKEFILE_PATH}/up-and-running/*.hurl

.PHONY: notus
notus:
	${HURL_BASE} ${MAKEFILE_PATH}/notus/*.hurl

.PHONY: dump-notus
dump-notus:
	${HURL_BASE} --curl rofl ${MAKEFILE_PATH}/notus/*.hurl


.PHONY: scans
scans:
	${HURL_BASE} ${MAKEFILE_PATH}/scans/*.hurl

.PHONY: $(SCANS_USER_FLOW)
$(SCANS_USER_FLOW):
	$(eval SCAN_CONFIG := $(patsubst scans-user-flow-%,%,$@))
	${HURL_BASE} --variable scan_config=${SCAN_CONFIG}.json ${MAKEFILE_PATH}/scans-user-flows/*.hurl

