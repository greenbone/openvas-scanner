# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

# OpenVAS Testsuite for the NASL interpreter
# Description: Tests for the nasl socket functions

# NB: This script is currently not intended as a regression tests.
# The problem is that we don't have an infrastructure to run local TLS
# test servers.  However, you may use this script to manually check
# stuff, for example by running:
#
# ../openvas-nasl -X -t greenbone.net test_socket.nasl
#

if (!defined_func("testcase_start")) {
  include("testsuiteinit.nasl");
}

target_port = 443;

function test_open_sock_tcp_tlscustom()
{
    local_var sock, certlist, cert, name, i, j;

  testcase_start(string("test_open_sock_tcp_tlscustom"));

  sock = open_sock_tcp(target_port,
                       transport:ENCAPS_TLScustom,
                       priority:strcat("NONE:+VERS-TLS1.0:",
                                       "+AES-256-CBC:+AES-128-CBC:",
                                       "+RSA:+DHE-RSA:+DHE-DSS:+SHA1"));
  if (sock > 0) {
      testcase_ok();
      display("\tencaps:     ", get_sock_info(sock, "encaps", asstring:1),"\n");
      display("\ttls-proto:  ", get_sock_info(sock, "tls-proto"), "\n");
      display("\ttls-kx:     ", get_sock_info(sock, "tls-kx"), "\n");
      display("\ttls-cipher: ", get_sock_info(sock, "tls-cipher"), "\n");
      display("\ttls-mac:    ", get_sock_info(sock, "tls-mac"), "\n");
      display("\ttls-comp:   ", get_sock_info(sock, "tls-comp"), "\n");
      display("\ttls-auth:   ", get_sock_info(sock, "tls-auth"), "\n");
      display("\ttls-ctype:  ", get_sock_info(sock, "tls-certtype"), "\n");
      certlist = get_sock_info(sock, "tls-cert");
      display("\ttls-cert: n=", max_index(certlist), "\n");
      if (defined_func("cert_open")) {
        for (i=0; i < max_index(certlist); i++) {
          cert = cert_open(certlist[i]);
          if (!cert)
            display("\ttls_cert: ",i,": error parsing certificate\n");
          else {
            display("\ttls_cert: ",i,":     serial: ",
                    toupper(hexstr(cert_query(cert, "serial"))),"\n");
            # Note: we use raw_string here to avoid a NASL warning
            # about the unknown escape sequence "\,", which is valid
            # RFC-2253 syntax. For a real output we would need to
            # parse a DN into its parts, to avoid those escape
            # conflicts.
            display("\ttls_cert: ",i,":     issuer: ",
                    raw_string(cert_query(cert, "issuer")),"\n");
            display("\ttls_cert: ",i,":    subject: ",
                    raw_string(cert_query(cert, "subject")),"\n");
            for(j=1; (name = cert_query(cert, "subject", idx:j)); j++)
                display("\ttls_cert: ",i,": altsubject: ", name, "\n");
            display("\ttls_cert: ",i,": not-before: ",
                    cert_query(cert, "not-before"),"\n");
            display("\ttls_cert: ",i,":  not-after: ",
                    cert_query(cert, "not-after"),"\n");

            hostnames = cert_query(cert, "hostnames");
            for (j=0; j < max_index(hostnames); j++) {
                display("\ttls_cert: ",i,":   hostname: ", hostnames[j], "\n");
            }
            cert_close(cert);
          }
        }



      }

  }
  else
      testcase_failed();
}

test_open_sock_tcp_tlscustom();

#eof
