#!/bin/sh
# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

set -xe

openssl req -nodes \
          -x509 \
          -days 3650 \
          -newkey rsa:4096 \
          -keyout ca.key \
          -out ca.cert \
          -sha256 \
          -batch \
          -subj "/CN=ponytown RSA CA"

openssl req -nodes \
          -newkey rsa:3072 \
          -keyout inter.key \
          -out inter.req \
          -sha256 \
          -batch \
          -subj "/CN=ponytown RSA level 2 intermediate"

openssl x509 -req \
            -in inter.req \
            -out inter.cert \
            -CA ca.cert \
            -CAkey ca.key \
            -sha256 \
            -days 3650 \
            -set_serial 123 \
            -extensions v3_inter -extfile ../openssl.cnf

