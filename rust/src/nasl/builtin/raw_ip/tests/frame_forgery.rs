// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL frame forgery and arp functions
use crate::nasl::test_prelude::*;

#[test]
fn get_local_mac_address_from_ip() {
    let mut t = TestBuilder::default();
    t.ok(
        "get_local_mac_address_from_ip(127.0.0.1);",
        "00:00:00:00:00:00",
    );
    t.ok(
        r#"get_local_mac_address_from_ip("127.0.0.1");"#,
        "00:00:00:00:00:00",
    );
    t.ok(
        r#"get_local_mac_address_from_ip("::1");"#,
        "00:00:00:00:00:00",
    );
}

#[test]
fn forge_frame() {
    let mut t = TestBuilder::default();
    t.run(r#"src = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);"#);
    t.run(r#"dst = "0a:0b:0c:0d:0e:0f";"#);
    t.ok(r#"a = forge_frame(src_haddr: src , dst_haddr: dst,ether_proto: 0x0806, payload: "abcd" );"#
         , vec![
             0x0au8, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x06,
             0x61, 0x62, 0x63, 0x64
         ]);
    t.run(r#"dump_frame(frame:a);"#);
}

#[test]
fn send_frame() {
    let mut t = TestBuilder::default();
    t.run(r#"src = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);"#);
    t.run(r#"dst = "0a:0b:0c:0d:0e:0f";"#);
    t.ok(r#"a = forge_frame(src_haddr: src , dst_haddr: dst, ether_proto: 0x0806, payload: "abcd");"#
         , vec![
             0x0au8, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x06,
             0x61, 0x62, 0x63, 0x64
         ]);
    t.ok(
        r#"send_frame(frame: a, pcap_active: FALSE);"#,
        NaslValue::Null,
    );
    t.ok(
        r#"send_frame(frame: a, pcap_active: TRUE);"#,
        NaslValue::Null,
    );
    t.ok(
        r#"send_frame(frame: a, pcap_active: TRUE, pcap_filter: "arp", timeout: 2);"#,
        NaslValue::Null,
    );
}
