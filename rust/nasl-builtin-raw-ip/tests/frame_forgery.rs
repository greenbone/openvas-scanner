// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL frame forgery and arp functions
#[cfg(test)]
mod tests {
    use nasl_builtin_std::ContextFactory;
    use nasl_interpreter::nasl_test_custom_context;
    use nasl_syntax::NaslValue;

    fn setup_context() -> ContextFactory<nasl_syntax::NoOpLoader, storage::DefaultDispatcher> {
        let mut context = ContextFactory::default();
        context.functions.push_executer(nasl_builtin_raw_ip::RawIp);
        context
    }

    #[test]
    fn get_local_mac_address_from_ip() {
        let context = setup_context();
        nasl_test_custom_context! {
            context,
            "get_local_mac_address_from_ip(127.0.0.1);" == "00:00:00:00:00:00",
            r#"get_local_mac_address_from_ip("127.0.0.1");"# == "00:00:00:00:00:00",
            r#"get_local_mac_address_from_ip("::1");"# == "00:00:00:00:00:00",
        }
    }

    #[test]
    fn forge_frame() {
        let context = setup_context();
        nasl_test_custom_context! {
            context,
            r#"src = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);"#,
            r#"dst = "0a:0b:0c:0d:0e:0f";"#,
            r#"a = forge_frame(src_haddr: src , dst_haddr: dst,ether_proto: 0x0806, payload: "abcd" );"#
                == vec![
                    0x0au8, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x06,
                    0x61, 0x62, 0x63, 0x64
                ],
            r#"dump_frame(frame:a);"#,
        }
    }

    #[test]
    fn send_frame() {
        let context = setup_context();
        nasl_test_custom_context! {
            context,
            r#"src = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);"#,
            r#"dst = "0a:0b:0c:0d:0e:0f";"#,
            r#"a = forge_frame(src_haddr: src , dst_haddr: dst, ether_proto: 0x0806, payload: "abcd");"#
                == vec![
                    0x0au8, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x06,
                    0x61, 0x62, 0x63, 0x64
                ],
            r#"send_frame(frame: a, pcap_active: FALSE);"# == NaslValue::Null,
            r#"send_frame(frame: a, pcap_active: TRUE);"# == NaslValue::Null,
            r#"send_frame(frame: a, pcap_active: TRUE, filter: "arp", timeout: 2);"# == NaslValue::Null,
        }
    }
}
