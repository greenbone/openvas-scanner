# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

.PHONY: build run-with-certs

MAKEFILE_PATH := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

ifdef TARGET_HOSTNAME
TARGET := $(TARGET_HOSTNAME)
else
TARGET := 127.0.0.1
endif

ifdef OPENVASD
SERVER := $(OPENVASD)
else
SERVER := http://127.0.0.1:8080
endif

ifndef SCAN_CONFIG
SCAN_CONFIG := ./simple_scan_ssh_only.json
endif

ifndef CARGO
	CARGO := cargo
endif

ifndef TARGET_USERNAME
	TARGET_USERNAME := noname
	TARGET_PASSWORD := nopass
endif

all: build run-with-certs

build: prepare-scan
	${CARGO} build

run:
	cargo test

prepare-scan:
	sed -i 's|<username>|'$(TARGET_USERNAME)'|' simple_scan_ssh_only.json
	sed -i 's|<password>|'$(TARGET_PASSWORD)'|' simple_scan_ssh_only.json
	sed -i 's|<hostname>|'$(TARGET)'|' simple_scan_ssh_only.json
