#!/bin/sh
# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

set -xe

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout end.key \
          -out end.req \
          -sha256 \
          -batch \
          -subj "/CN=testclient.com"

openssl rsa \
          -in end.key \
          -out client.key

openssl x509 -req \
            -in end.req \
            -out end.cert \
            -CA inter.cert \
            -CAkey inter.key \
            -sha256 \
            -days 2000 \
            -set_serial 456 \
            -extensions v3_end -extfile ../openssl.cnf

mv end.cert client.cert
