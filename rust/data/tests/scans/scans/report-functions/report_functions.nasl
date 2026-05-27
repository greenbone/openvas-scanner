# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.9900001");
  script_version("2026-05-27T00:00:00+0000");
  script_tag(name:"creation_date", value:"2026-05-27 00:00:00 +0000 (Wed, 27 May 2026)");
  script_tag(name:"last_modification", value:"2026-05-27 00:00:00 +0000 (Wed, 27 May 2026)");
  script_name("OpenVAS compatibility report-functions fixture");
  script_category(ACT_GATHER_INFO);
  script_family("OpenVAS Compatibility Tests");
  exit(0);
}

log_message(data:"compat log tcp/80", port:80, proto:"tcp");
security_message(data:"compat alarm tcp/443", port:443, proto:"tcp");
security_message(data:"compat alarm udp/53", port:53, proto:"udp");
error_message(data:"compat error tcp/25", port:25, proto:"tcp");

exit(0);
