// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL frame forgery and arp functions
#[cfg(test)]
mod tests {

    use nasl_builtin_raw_ip::RawIp;
    use nasl_builtin_std::ContextFactory;
    use crate::nasl::utils::{error::FnError, Executor};
    use crate::nasl::interpreter::test_utils::TestBuilder;
    use crate::nasl::syntax::NaslValue;

    /// Copy from a slice in safe way, performing the necessary test to avoid panicking
    fn safe_copy_from_slice(
        d_buf: &mut [u8],
        d_init: usize,
        d_fin: usize,
        o_buf: &[u8],
        o_init: usize,
        o_fin: usize,
    ) -> Result<(), FnError> {
        let o_range = o_fin - o_init;
        let d_range = d_fin - d_init;
        if d_buf.len() < d_range
            || o_buf.len() < o_range
            || o_range != d_range
            || d_buf.len() < d_fin
            || o_buf.len() < o_fin
        {
            return Err(FnError::Diagnostic(
                "Error copying from slice. Index out of range".to_string(),
                Some(NaslValue::Null),
            ));
        }
        d_buf[d_init..d_fin].copy_from_slice(&o_buf[o_init..o_fin]);
        Ok(())
    }

    pub fn setup() -> TestBuilder<crate::nasl::syntax::NoOpLoader, storage::DefaultDispatcher> {
        let t = TestBuilder::default();
        let mut context = ContextFactory::default();
        context.functions = Executor::single(RawIp);
        t.with_context(context)
    }

    #[test]
    fn forge_packet() {
        let mut t = setup();
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
                69u8, 0, 0, 40, 210, 4, 0, 0, 255, 6, 104, 109, 192, 168, 0, 1, 192, 168, 0, 12,
                19, 216, 0, 80, 0, 0, 3, 232, 0, 0, 0, 0, 80, 33, 0, 0, 22, 86, 0, 0,
            ],
        );
    }

    #[test]
    fn modify_elements() {
        let mut t = setup();
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
        let mut t = setup();
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
        let mut t = setup();
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
        t.run("tcp_packet = insert_tcp_options(tcp: tcp_packet, 3, 2);");
        t.ok("opt = get_tcp_option(tcp: tcp_packet, option: 3);", 2);
    }

    #[test]
    fn forge_udp() {
        let mut t = setup();
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
                                        uh_len:   8,
                                        th_sum:   0,
                                        data: "1234");"#,
            vec![
                69u8, 0, 0, 32, 210, 4, 0, 0, 255, 17, 104, 108, 192, 168, 0, 1, 192, 168, 0, 10,
                19, 216, 0, 80, 0, 8, 5, 240, 49, 50, 51, 52,
            ],
        );
    }

    #[test]
    fn forge_icmp() {
        let mut t = setup();
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
                69u8, 0, 0, 32, 210, 4, 0, 0, 255, 1, 104, 124, 192, 168, 0, 1, 192, 168, 0, 10, 8,
                0, 145, 153, 1, 0, 1, 0, 49, 50, 51, 52,
            ],
        );
    }

    #[test]
    fn forge_igmp() {
        let mut t = setup();
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
                69u8, 0, 0, 28, 210, 4, 0, 0, 255, 2, 104, 127, 192, 168, 0, 1, 192, 168, 0, 10,
                17, 10, 14, 244, 224, 0, 0, 1,
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
    fn copy_from_slice_safe() {
        let mut a = [1u8, 2u8, 3u8, 4u8];
        let b = [b'a', b'b', b'c', b'd'];
        let alen = a.len();
        // different range size between origin and destination
        assert_eq!(
            safe_copy_from_slice(&mut a, 0, 2, &b, 0, b.len()),
            Err(FnError::Diagnostic(
                "Error copying from slice. Index out of range".to_string(),
                Some(NaslValue::Null)
            ))
        );

        // different range size between origin and destination
        assert_eq!(
            safe_copy_from_slice(&mut a, 0, alen, &b, 0, 2),
            Err(FnError::Diagnostic(
                "Error copying from slice. Index out of range".to_string(),
                Some(NaslValue::Null)
            ))
        );

        // out of index in the destination range
        assert_eq!(
            safe_copy_from_slice(&mut a, 1, alen + 1, &b, 0, b.len()),
            Err(FnError::Diagnostic(
                "Error copying from slice. Index out of range".to_string(),
                Some(NaslValue::Null)
            ))
        );

        let _r = safe_copy_from_slice(&mut a, 0, 2, &b, 0, 2);
        assert_eq!(a, [b'a', b'b', 3u8, 4u8]);
    }
}
