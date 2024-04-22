// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::gcrypt_get_error_string;

extern "C" {
    pub fn nasl_aes_mac_gcm(
        data: *const ::std::os::raw::c_uchar,
        data_len: usize,
        key: *const ::std::os::raw::c_uchar,
        key_len: usize,
        iv: *const ::std::os::raw::c_uchar,
        iv_len: usize,
        out: *mut *mut ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn nasl_get_aes_mac_gcm_len() -> ::std::os::raw::c_uint;
}

pub fn aes_gmac(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    unsafe {
        let size = nasl_get_aes_mac_gcm_len() as usize;
        let mut ret: Vec<u8> = Vec::with_capacity(size);

        let mut out = ret.as_mut_ptr();
        let err = nasl_aes_mac_gcm(
            data.as_ptr(),
            data.len(),
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            iv.len(),
            &mut out as *mut _,
        );
        if err != 0 {
            return Err(gcrypt_get_error_string(err));
        }
        Ok(ret)
    }
}
