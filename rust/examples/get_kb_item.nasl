# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

set_kb_item(name: "test", value: 1);
set_kb_item(name: "test", value: 2);
set_kb_item(name: "test", value: 3);
set_kb_item(name: "test", value: 4);
set_kb_item(name: "test", value: 5);
display(get_kb_item("test"));
