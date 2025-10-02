#!/bin/sh
# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
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

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout end.key \
          -out end.req \
          -sha256 \
          -batch \
          -subj "/CN=testserver.com"

openssl rsa \
          -in end.key \
          -out client.rsa

openssl x509 -req \
            -in inter.req \
            -out inter.cert \
            -CA ca.cert \
            -CAkey ca.key \
            -sha256 \
            -days 3650 \
            -set_serial 123 \
            -extensions v3_inter -extfile "$dir/../openssl.cnf"

openssl x509 -req \
            -in end.req \
            -out end.cert \
            -CA inter.cert \
            -CAkey inter.key \
            -sha256 \
            -days 2000 \
            -set_serial 456 \
            -extensions v3_end -extfile "$dir/../openssl.cnf"

cat end.cert inter.cert ca.cert > client.pem
rm *.key *.cert *.req
