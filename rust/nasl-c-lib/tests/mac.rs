// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;
#[cfg(test)]
mod tests {
    use nasl_c_lib::cryptographic::mac::aes_gmac;

    use crate::helper::decode_hex;

    #[test]
    fn aes_mac_gcm() {
        let key = decode_hex("7fddb57453c241d03efbed3ac44e371c").unwrap();
        let data = decode_hex("d5de42b461646c255c87bd2962d3b9a2").unwrap();
        let iv = decode_hex("ee283a3fc75575e33efd48").unwrap();

        let result = aes_gmac(data.as_slice(), key.as_slice(), iv.as_slice());

        assert!(result.is_ok());
    }
}
