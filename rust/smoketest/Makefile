# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

.PHONY: build run

MAKEFILE_PATH := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

ifndef CARGO
	CARGO := cargo
endif

all: build run

build:
	${CARGO} build

run:
	../target/debug/smoketest --openvasd http://127.0.0.1:3000 --scan-config ./simple_scan_ssh_only.json --api-key $(API_KEY)

run-with-certs:
	../target/debug/smoketest --openvasd https://127.0.0.1:3000 --cert $(CLIENT_CERT) --key $(CLIENT_KEY) --scan-config ./simple_scan_ssh_only.json --api-key $(API_KEY)

