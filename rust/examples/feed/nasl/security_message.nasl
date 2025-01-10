# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

if (description)
{
  script_oid("0.0.0.0.0.0.0.0.0.4");
  script_version("2023-02-23T13:33:44+0000");
  script_tag(name:"last_modification", value:"2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)");
  script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Application Server Detection (HTTP)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_tag(name:"summary", value:"HTTP AS detection");
  script_xref(name:"URL", value:"https://greenbone.net");
  script_dependencies("1.nasl");
  exit(0);
}
security_message(data: "0.0.0.0.0.0.0.0.0.4", uri: "file:///tmp/openvasd/oids");
