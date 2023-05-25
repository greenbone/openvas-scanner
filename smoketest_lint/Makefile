# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

.PHONY: build run clean all

build:
	go build -o run cmd/main.go

run: build
	./run

clean:
	rm run

all: build run clean

