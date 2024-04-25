# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

display("Starting...");
h = http2_handle();
display(h);

i = http2_set_custom_header(handle: h, header_item: "X-API-KEY: changeme");
i = http2_set_custom_header(handle: h, header_item: "content-type: application/json");

# valid for openvasd
r = http2_get(handle:h, port:3000, item:"/health/ready", schema:"https");
display("response: ", r);

rc = http2_get_response_code(handle:h);

display("return code: ", rc);

http2_close_handle(h);
