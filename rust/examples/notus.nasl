# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pkg_list = "libc6-1.28-10+deb10u2, libc-dev-bin-2.28-10+deb10u2";

results = notus(product: "debian_10", pkg_list: pkg_list);

if(!isnull(results)) {
    foreach res (results) {
        oid = res["oid"];
        msg = res["message"];
        display(oid);
        display(msg);
    }
} else {
    ret = notus_error();
    display(ret);
}
