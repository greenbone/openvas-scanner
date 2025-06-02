// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL frame forgery and arp functions

use crate::nasl::{
    builtin::raw_ip::packet_forgery::PacketForgery, test_prelude::*, utils::DefineGlobalVars,
};

#[test]
fn forge_packet() {
    let mut t = TestBuilder::default();
    t.ok(
        r#"ip_packet = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 1234,
                        ip_p : 0x06,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : 192.168.0.1,
                        ip_dst : 192.168.0.12);"#,
        vec![
            69u8, 0, 0, 20, 210, 4, 0, 0, 255, 6, 104, 129, 192, 168, 0, 1, 192, 168, 0, 12,
        ],
    );
    t.ok(
        r#"tcp_packet = forge_tcp_packet(ip:       ip_packet,
                                th_sport: 5080,
                                th_dport: 80,
                                th_seq:   1000,
                                th_ack:   0,
                                th_x2:    0,
                                th_off:   5,
                                th_flags: 33,
                                th_win:   0,
                                th_sum:   0,
                                th_urp:   0);"#,
        vec![
            69u8, 0, 0, 40, 210, 4, 0, 0, 255, 6, 104, 109, 192, 168, 0, 1, 192, 168, 0, 12, 19,
            216, 0, 80, 0, 0, 3, 232, 0, 0, 0, 0, 80, 33, 0, 0, 22, 86, 0, 0,
        ],
    );
}

#[test]
fn modify_elements() {
    let mut t = TestBuilder::default();
    t.run(
        r#"ip_packet = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 1234,
                        ip_p : 0x06,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : 192.168.0.1,
                        ip_dst : 192.168.0.12);"#,
    );
    t.ok(
        r#"elem = get_ip_element(ip: ip_packet, element: "ip_ttl");"#,
        255,
    );
    t.run(r#"ip_packet = set_ip_elements(ip: ip_packet, ip_ttl: 127, ip_src: 192.168.0.10);"#);
    t.ok(
        r#"elem = get_ip_element(ip: ip_packet, element: "ip_ttl");"#,
        127,
    );
}

#[test]
fn ip_opts() {
    let mut t = TestBuilder::default();
    t.run(
        r#"ip_packet = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 1234,
                        ip_p : 0x06,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : 192.168.0.1,
                        ip_dst : 192.168.0.12);"#,
    );
    t.run(r#"ip_packet = insert_ip_options(ip: ip_packet, code: 131, length:5, value: "12");"#);
    t.ok(
        r#"opt = get_ip_element(ip: ip_packet, element: "ip_hl");"#,
        8,
    );
}

#[test]
fn tcp_opts() {
    let mut t = TestBuilder::default();
    t.run(
        r#"ip_packet = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 1234,
                        ip_p : 0x06,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : 192.168.0.1,
                        ip_dst : 192.168.0.12);"#,
    );
    t.run(
        r#"tcp_packet = forge_tcp_packet(ip:       ip_packet,
                                data:     1234,
                                th_sport: 5080,
                                th_dport: 80,
                                th_seq:   1000,
                                th_ack:   0,
                                th_x2:    0,
                                th_off:   5,
                                th_flags: 33,
                                th_win:   0,
                                th_sum:   0,
                                th_urp:   0);"#,
    );
    t.run("tcp_packet_opts = insert_tcp_options(tcp: tcp_packet, 3, 2);");
    t.ok("opt = get_tcp_option(tcp: tcp_packet_opts, option: 3);", 2);
}

#[test]
fn forge_udp() {
    let mut t = TestBuilder::default();
    t.ok(
        r#"ip_packet = forge_ip_packet(ip_v : 4,
                                ip_hl : 5,
                                ip_tos : 0,
                                ip_len : 20,
                                ip_id : 1234,
                                ip_p : 0x11,
                                ip_ttl : 255,
                                ip_off : 0,
                                ip_src : 192.168.0.1,
                                ip_dst : 192.168.0.10);"#,
        vec![
            69u8, 0, 0, 20, 210, 4, 0, 0, 255, 17, 104, 120, 192, 168, 0, 1, 192, 168, 0, 10,
        ],
    );
    t.ok(
        r#"udp_packet = forge_udp_packet(ip:       ip_packet,
                                        uh_sport: 5080,
                                        uh_dport: 80,
                                        uh_ulen:   8,
                                        uh_sum:   0,
                                        update_ip_len: TRUE,
                                        data: "1234");"#,
        vec![
            69u8, 0, 0, 32, 210, 4, 0, 0, 255, 17, 104, 108, 192, 168, 0, 1, 192, 168, 0, 10, 19,
            216, 0, 80, 0, 8, 5, 240, 49, 50, 51, 52,
        ],
    );
}

#[test]
fn forge_icmp() {
    let mut t = TestBuilder::default();
    t.run(
        r#"ip_packet = forge_ip_packet(ip_v : 4,
                    ip_hl : 5,
                    ip_tos : 0,
                    ip_len : 20,
                    ip_id : 1234,
                    ip_p : 0x01, #IPPROTO_ICMP
                    ip_ttl : 255,
                    ip_off : 0,
                    ip_src : 192.168.0.1,
                    ip_dst : 192.168.0.10);"#,
    );
    t.ok(
        r#"icmp = forge_icmp_packet(ip: ip_packet,
                    icmp_type: 8,
                    icmp_code: 0,
                    icmp_seq:   1,
                    icmp_id:   1,
                    data: "1234");"#,
        vec![
            69u8, 0, 0, 32, 210, 4, 0, 0, 255, 1, 104, 124, 192, 168, 0, 1, 192, 168, 0, 10, 8, 0,
            145, 153, 1, 0, 1, 0, 49, 50, 51, 52,
        ],
    );
}

#[test]
fn forge_igmp() {
    let mut t = TestBuilder::default();
    t.run(
        r#"ip_packet = forge_ip_packet(ip_v : 4,
                    ip_hl : 5,
                    ip_tos : 0,
                    ip_len : 20,
                    ip_id : 1234,
                    ip_p : 0x02, #IPPROTO_IGMP
                    ip_ttl : 255,
                    ip_off : 0,
                    ip_src : 192.168.0.1,
                    ip_dst : 192.168.0.10);"#,
    );
    t.ok(
        r#"igmp = forge_igmp_packet(
                    ip: ip_packet,
                    type: 0x11,
                    code: 10,
                    group: 224.0.0.1,
                    );"#,
        vec![
            69u8, 0, 0, 28, 210, 4, 0, 0, 255, 2, 104, 127, 192, 168, 0, 1, 192, 168, 0, 10, 17,
            10, 14, 244, 224, 0, 0, 1,
        ],
    );
}

#[test]
#[should_panic]
fn copy_from_slice_panic() {
    let mut a = [1u8, 2u8, 3u8, 4u8];
    let b = [b'a', b'b', b'c', b'd'];

    // this should panic
    a[..2].copy_from_slice(&b[..b.len()]);
}

#[test]
fn forge_icmp_v6_packet() {
    let mut t = TestBuilder::default().with_target("5858::2".to_string());
    t.ok(
        r#"ip6_packet = forge_ip_v6_packet( ip6_v: 6,
                                ip6_p: 0x3a,
                                ip6_hlim: 128,
                                ip6_src: "5858::1",
                                ip6_dst: "5858::2");"#,
        vec![
            96u8, 0, 0, 0, 0, 0, 58, 128, 88, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 88, 88,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ],
    );
    t.ok(
        r#"icmp = forge_icmp_v6_packet( ip6:ip6_packet,
                             icmp_type:128,
                             icmp_code:1,
                             icmp_seq:2,
                             icmp_id: 1,
                             icmp_cksum: 0
                             );"#,
        vec![
            96u8, 0, 0, 0, 0, 8, 58, 128, 88, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 88, 88,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 128, 1, 204, 8, 1, 0, 2, 0,
        ],
    );
}

#[test]
fn modify_ipv6_elements() {
    let mut t = TestBuilder::default().with_target("5858::2".to_string());
    t.run(
        r#"ip6_packet = forge_ip_v6_packet( ip6_v: 6,
                                ip6_p: 0x3a,
                                ip6_hlim: 128,
                                ip6_src: "5858::1",
                                ip6_dst: "5858::2");"#,
    );
    t.ok(
        r#"elem = get_ip_v6_element(ip6: ip6_packet, element: "ip6_hlim");"#,
        128,
    );
    t.run(
        r#"ip6_packet = set_ip_v6_elements(ip6: ip6_packet, ip6_hlim: 127, ip6_src: "5858::3");"#,
    );
    t.ok(
        r#"elem = get_ip_v6_element(ip6: ip6_packet, element: "ip6_hlim");"#,
        127,
    );
}

#[test]
fn forge_udp_v6() {
    let mut t = TestBuilder::default().with_target("5858::2".to_string());

    t.run(
        r#"ip6_packet = forge_ip_v6_packet( ip6_v: 6,
                                ip6_p: 0x3a,
                                ip6_hlim: 128,
                                ip6_src: "5858::1",
                                ip6_dst: "5858::2");"#,
    );
    t.ok(
        r#"udp6_packet = forge_udp_v6_packet(ip6:       ip6_packet,
                                        uh_sport: 5080,
                                        uh_dport: 80,
                                        uh_ulen:   8,
                                        uh_sum:   0,
                                        update_ip6_len: TRUE,
                                        data: "1234");"#,
        vec![
            96u8, 0, 0, 0, 0, 12, 58, 128, 88, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 88,
            88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 19, 216, 0, 80, 0, 8, 214, 152, 49, 50,
            51, 52,
        ],
    );
    t.ok(
        r#"udp6_packet = set_udp_v6_elements(udp: udp6_packet, uh_sport: 33000);"#,
        vec![
            96u8, 0, 0, 0, 0, 12, 58, 128, 88, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 88,
            88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 128, 232, 0, 80, 0, 8, 105, 136, 49, 50,
            51, 52,
        ],
    );

    t.ok(
        r#"get_udp_v6_element(udp:udp6_packet, element:"uh_sport");"#,
        33000,
    );
}

#[test]
fn forge_tcp_v6() {
    let mut t = TestBuilder::default().with_target("5858::2".to_string());

    t.run(
        r#"ip6_packet = forge_ip_v6_packet( ip6_v: 6,
                                ip6_p: 0x3a,
                                ip6_hlim: 128,
                                ip6_src: "5858::1",
                                ip6_dst: "5858::2");"#,
    );
    t.ok(
        r#"tcp6_packet = forge_tcp_v6_packet(ip6:       ip6_packet,
                                th_sport: 5080,
                                th_dport: 80,
                                th_seq:   1000,
                                th_ack:   0,
                                th_x2:    0,
                                th_off:   5,
                                th_flags: 33,
                                th_win:   0,
                                th_sum:   0,
                                th_urp:   0);"#,
        vec![
            96u8, 0, 0, 0, 0, 20, 58, 128, 88, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 88,
            88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 19, 216, 0, 80, 0, 0, 3, 232, 0, 0, 0, 0,
            80, 33, 0, 0, 231, 0, 0, 0,
        ],
    );
    t.run(r#"tcp6_packet = set_tcp_v6_elements(tcp: tcp6_packet, th_sport: 33000);"#);
    t.ok(
        r#"get_tcp_v6_element(tcp:tcp6_packet, element:"th_sport");"#,
        33000,
    );
    t.run("tcp_packet_opts = insert_tcp_v6_options(tcp: tcp6_packet, 3, 2);");
    t.ok(
        "opt = get_tcp_v6_option(tcp: tcp_packet_opts, option: 3);",
        2,
    );
}

#[test]
fn global_variables() {
    // Make sure all of the variables that this set defines
    // are available
    let mut t = TestBuilder::default();
    for (name, val) in PacketForgery::get_global_vars() {
        t.ok(format!("{name};"), val);
    }
}
