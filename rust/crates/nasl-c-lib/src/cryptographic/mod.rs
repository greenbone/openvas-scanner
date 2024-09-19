// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::ffi::CStr;

pub mod mac;

extern "C" {
    pub fn gcrypt_strerror(err: ::std::os::raw::c_int) -> *const ::std::os::raw::c_char;
}

fn gcrypt_get_error_string(error: i32) -> &'static str {
    let char_ptr = unsafe { gcrypt_strerror(error) };
    let c_str = unsafe { CStr::from_ptr(char_ptr) };
    c_str.to_str().unwrap_or("Invalid UTF8")
}
