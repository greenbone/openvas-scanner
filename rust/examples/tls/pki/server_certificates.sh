#!/bin/sh
# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

set -xe

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout end.key \
          -out end.req \
          -sha256 \
          -batch \
          -subj "/CN=testserver.com"

openssl rsa \
          -in end.key \
          -out server.key

openssl x509 -req \
            -in end.req \
            -out end.cert \
            -CA inter.cert \
            -CAkey inter.key \
            -sha256 \
            -days 2000 \
            -set_serial 456 \
            -extensions v3_end -extfile "$dir/openssl.cnf"

cp end.cert server.cert

