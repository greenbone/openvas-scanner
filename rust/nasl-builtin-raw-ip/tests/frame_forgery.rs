// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL frame forgery and arp functions
#[cfg(test)]
mod tests {

    //use super::convert_vec_into_mac_address;

    use nasl_builtin_std::ContextBuilder;
    use nasl_builtin_utils::Register;
    use nasl_interpreter::CodeInterpreter;
    use nasl_syntax::NaslValue;

    #[test]
    fn get_local_mac_address_from_ip() {
        let code = r#"
        get_local_mac_address_from_ip(127.0.0.1);
        get_local_mac_address_from_ip("127.0.0.1");
        get_local_mac_address_from_ip("::1");
        "#;
        let register = Register::default();
        let mut binding = ContextBuilder::default();
        binding.functions.push_executer(nasl_builtin_raw_ip::RawIp);
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("00:00:00:00:00:00".to_string())))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("00:00:00:00:00:00".to_string())))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("00:00:00:00:00:00".to_string())))
        );
    }

    #[test]
    fn forge_frame() {
        let code = r#"
        src = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        dst = "0a:0b:0c:0d:0e:0f";
        a = forge_frame(src_haddr: src , dst_haddr: dst,
        ether_proto: 0x0806, payload: "abcd" );
        dump_frame(frame:a);
        "#;
        let register = Register::default();
        let mut binding = ContextBuilder::default();
        binding.functions.push_executer(nasl_builtin_raw_ip::RawIp);

        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(vec![
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x06,
                0x61, 0x62, 0x63, 0x64
            ])))
        );
        // This dumps the forged frame. To see it in the tests output, run the tests with
        // `cargo test -- --nocapture`
        parser.next();
    }
    #[test]
    fn send_frame() {
        let code = r#"
        src = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        dst = "0a:0b:0c:0d:0e:0f";
        a = forge_frame(src_haddr: src , dst_haddr: dst,
        ether_proto: 0x0806, payload: "abcd" );
        send_frame(frame: a, pcap_active: FALSE);
        send_frame(frame: a, pcap_active: TRUE);
        send_frame(frame: a, pcap_active: TRUE, filter: "arp", timeout: 2);
        "#;
        let mut binding = ContextBuilder::default();
        binding.functions.push_executer(nasl_builtin_raw_ip::RawIp);
        let context = binding.build();
        let register = Register::default();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(vec![
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x06,
                0x61, 0x62, 0x63, 0x64
            ])))
        );

        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }
}
