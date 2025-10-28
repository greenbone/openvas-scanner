# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

oid = "1.3.6.1.2.1.1.5.0";
protocol = "udp";
port = 161;
community = "public";

display("version 1");
ret = snmpv1_get( port:port, oid:oid, protocol:protocol, community:community );
display (ret, "\n");
ret = snmpv1_getnext( port:port, protocol:protocol, community:community );
display (ret, "\n");

display("version 2c");
ret = snmpv2c_get( port:port, oid:oid, protocol:protocol, community:community );
display (ret, "\n");

ret = snmpv2c_getnext( port:port, protocol:protocol, community:community );
display (ret, "\n");

display("version 3");
user = "username";
pass = "pass123456";
passph = "keypass123456";

ret = snmpv3_get(port:port, protocol:"udp", username:user, oid:oid,
	          authpass:pass, authproto:"sha1", privpass:passph,
                  privproto:"aes");

display (ret, "\n");
ret = snmpv3_getnext(port:port, protocol:"udp", username:user,
	          authpass:pass, authproto:"sha1", privpass:passph,
                  privproto:"aes");
display (ret, "\n");
