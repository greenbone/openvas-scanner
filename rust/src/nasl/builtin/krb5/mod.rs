// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use nasl_c_lib::krb5::{
    OKrb5Credential, OKrb5ErrorCode, OKrb5ErrorCode_O_KRB5_CONF_NOT_FOUND,
    OKrb5ErrorCode_O_KRB5_EXPECTED_NOT_NULL, OKrb5ErrorCode_O_KRB5_REALM_NOT_FOUND,
    OKrb5ErrorCode_O_KRB5_SUCCESS, OKrb5GSSContext, OKrb5Slice, OKrb5Target, OKrb5User,
    o_krb5_add_realm, o_krb5_find_kdc, o_krb5_gss_prepare_context, o_krb5_gss_session_key_context,
    o_krb5_gss_update_context, okrb5_error_code_to_string, okrb5_gss_init_context,
};
use nasl_function_proc_macro::nasl_function;
use std::os;
use std::sync::Mutex;
use std::{ffi::CStr, sync::Arc};
use thiserror::Error;

use crate::{
    function_set,
    nasl::{FnError, utils::function::StringOrData},
};

macro_rules! get_var_or_env {
    ($var:expr, $env:expr) => {
        $var.map(|x| x.to_string())
            .or(std::env::var($env).ok())
            .ok_or(Krb5Error::Var(
                stringify!($var).to_string(),
                $env.to_string(),
            ))
    };
}

fn error_code_to_string(code: OKrb5ErrorCode) -> String {
    let err = unsafe { okrb5_error_code_to_string(code) };
    if err.is_null() {
        return format!("Unknown error code: {}", code);
    }
    let c_str = unsafe { CStr::from_ptr(err) };
    let rust_string = c_str.to_string_lossy().into_owned();
    unsafe {
        libc::free(err as *mut libc::c_void);
    }
    rust_string
}

fn string_from_okrb5_slice(slice: OKrb5Slice) -> String {
    unsafe {
        let bytes = std::slice::from_raw_parts(slice.data as *const u8, slice.len);
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[derive(Debug, Error)]
pub enum Krb5Error {
    #[error("Expected {0} or env variable {1}")]
    Var(String, String),
    #[error(
        "[config_path: '{config_path}', realm: '{realm}', user: '{user}'] => {message} ({code})"
    )]
    Credential {
        config_path: String,
        realm: String,
        user: String,
        message: String,
        code: OKrb5ErrorCode,
    },
    #[error("Unable to prepare GSS context")]
    Context,
}

struct Krb5Credentials {
    _config_path: String,
    _realm: String,
    _kdc: String,
    _user: String,
    _password: String,
    _host: String,
    _service: String,
    cred: OKrb5Credential,
}

impl Krb5Credentials {
    fn new(
        config_path: String,
        realm: String,
        kdc: String,
        user: String,
        password: String,
        host: String,
        service: String,
    ) -> Self {
        let cred = Self::make_credential(
            &config_path,
            &realm,
            &kdc,
            &user,
            &password,
            &host,
            &service,
        );
        Self {
            _config_path: config_path,
            _realm: realm,
            _kdc: kdc,
            _user: user,
            _password: password,
            _host: host,
            _service: service,
            cred,
        }
    }

    fn make_credential(
        config_path: &str,
        realm: &str,
        kdc: &str,
        user: &str,
        password: &str,
        host: &str,
        service: &str,
    ) -> OKrb5Credential {
        OKrb5Credential {
            config_path: OKrb5Slice {
                data: config_path.as_ptr() as *mut os::raw::c_void,
                len: config_path.len(),
            },
            realm: OKrb5Slice {
                data: realm.as_ptr() as *mut os::raw::c_void,
                len: realm.len(),
            },
            kdc: OKrb5Slice {
                data: kdc.as_ptr() as *mut os::raw::c_void,
                len: kdc.len(),
            },
            user: OKrb5User {
                user: OKrb5Slice {
                    data: user.as_ptr() as *mut os::raw::c_void,
                    len: user.len(),
                },
                password: OKrb5Slice {
                    data: password.as_ptr() as *mut os::raw::c_void,
                    len: password.len(),
                },
            },
            target: OKrb5Target {
                host_name: OKrb5Slice {
                    data: host.as_ptr() as *mut os::raw::c_void,
                    len: host.len(),
                },
                service: OKrb5Slice {
                    data: service.as_ptr() as *mut os::raw::c_void,
                    len: service.len(),
                },
                domain: OKrb5Slice {
                    data: std::ptr::null_mut(),
                    len: 0,
                },
            },
        }
    }

    fn okrb5_credential(&self) -> &OKrb5Credential {
        &self.cred
    }
}

#[derive(Default)]
pub struct Krb5 {
    last_okrb5_result: OKrb5ErrorCode,
    cached_gss_context: Arc<Mutex<*mut OKrb5GSSContext>>,
    to_application: Arc<Mutex<*mut OKrb5Slice>>,
    gss_context_needs_more: bool,
}

impl Drop for Krb5 {
    fn drop(&mut self) {
        let to_application = *self.to_application.lock().unwrap();
        if !to_application.is_null() {
            unsafe {
                let slice = &*to_application;
                if !slice.data.is_null() {
                    libc::free(slice.data);
                }
                libc::free(to_application as *mut libc::c_void);
            }
        }

        // TODO: This block leads to munmap_chunk(): invalid pointer and Aborted (core dumped)
        // let cached_gss_context = *self.cached_gss_context.lock().unwrap();
        // if !cached_gss_context.is_null() {
        //     unsafe {
        //         okrb5_gss_free_context(cached_gss_context);
        //     }
        // }
    }
}

// SAFETY: Krb5 can be safely sent between threads because:
// - The raw pointers are stored behind Arc<Mutex<...>> for synchronization
// - Access to the pointers is guarded by mutex locks
// - The outer Arc<Mutex<...>> provides the thread-safe coordination
unsafe impl Send for Krb5 {}
unsafe impl Sync for Krb5 {}

impl Krb5 {
    #[nasl_function]
    fn krb5_is_failure(&self, code: Option<u32>) -> bool {
        let code = code.unwrap_or(self.last_okrb5_result);
        code != OKrb5ErrorCode_O_KRB5_SUCCESS
    }

    #[nasl_function]
    fn krb5_is_success(&self, code: Option<u32>) -> bool {
        let code = code.unwrap_or(self.last_okrb5_result);
        code == OKrb5ErrorCode_O_KRB5_SUCCESS
    }

    #[nasl_function]
    fn krb5_error_code_to_string(&self) -> String {
        error_code_to_string(self.last_okrb5_result)
    }

    fn build_krb5_credential(
        &mut self,
        config_path: Option<&str>,
        realm: Option<&str>,
        kdc: Option<&str>,
        user: Option<&str>,
        password: Option<&str>,
        host: Option<&str>,
        service: Option<&str>,
    ) -> Result<Krb5Credentials, Krb5Error> {
        let config_path = config_path
            .map(|x| x.to_string())
            .or(std::env::var("KRB5_CONFIG").ok())
            .unwrap_or("/etc/krb5.conf".to_string());

        let realm = get_var_or_env!(realm, "KRB5_REALM")?;
        let kdc = get_var_or_env!(kdc, "KRB5_KDC")?;
        let user = get_var_or_env!(user, "KRB5_USER")?;
        let password = get_var_or_env!(password, "KRB5_PASSWORD")?;
        let host = get_var_or_env!(host, "KRB5_TARGET_HOST")?;
        let service = service
            .map(|x| x.to_string())
            .or(std::env::var("KRB5_TARGET_SERVICE").ok())
            .unwrap_or("cifs".to_string());

        let credential = Krb5Credentials::new(
            config_path.clone(),
            realm.clone(),
            kdc.clone(),
            user.clone(),
            password.clone(),
            host.clone(),
            service,
        );

        let mut kdc_ptr: *mut i8 = std::ptr::null_mut();
        let code = unsafe { o_krb5_find_kdc(credential.okrb5_credential(), &mut kdc_ptr) };

        match code {
            OKrb5ErrorCode_O_KRB5_SUCCESS => {
                if !kdc_ptr.is_null() {
                    unsafe {
                        libc::free(kdc_ptr as *mut libc::c_void);
                    }
                }
            }
            code if code != OKrb5ErrorCode_O_KRB5_REALM_NOT_FOUND
                && code != OKrb5ErrorCode_O_KRB5_CONF_NOT_FOUND =>
            {
                return Err(Krb5Error::Credential {
                    config_path,
                    realm,
                    user,
                    message: error_code_to_string(code),
                    code,
                });
            }
            _ => {
                let code = unsafe {
                    o_krb5_add_realm(
                        credential.okrb5_credential(),
                        credential.okrb5_credential().kdc.data as *const i8,
                    )
                };
                if code != OKrb5ErrorCode_O_KRB5_SUCCESS {
                    return Err(Krb5Error::Credential {
                        config_path,
                        realm,
                        user,
                        message: error_code_to_string(code),
                        code,
                    });
                }
            }
        }

        Ok(credential)
    }

    #[nasl_function(named(config_path, realm, kdc, user, password, host))]
    fn krb5_find_kdc(
        &mut self,
        config_path: Option<&str>,
        realm: Option<&str>,
        kdc: Option<&str>,
        user: Option<&str>,
        password: Option<&str>,
        host: Option<&str>,
    ) -> Result<String, FnError> {
        let credential =
            self.build_krb5_credential(config_path, realm, kdc, user, password, host, None)?;
        let mut kdc_ptr: *mut i8 = std::ptr::null_mut();

        self.last_okrb5_result =
            unsafe { o_krb5_find_kdc(credential.okrb5_credential(), &mut kdc_ptr) };

        if self.last_okrb5_result != OKrb5ErrorCode_O_KRB5_SUCCESS {
            return Err(Krb5Error::Credential {
                config_path: string_from_okrb5_slice(credential.okrb5_credential().config_path),
                realm: string_from_okrb5_slice(credential.okrb5_credential().realm),
                user: string_from_okrb5_slice(credential.okrb5_credential().user.user),
                message: error_code_to_string(self.last_okrb5_result),
                code: self.last_okrb5_result,
            }
            .into());
        }

        if kdc_ptr.is_null() {
            return Ok(String::new());
        }

        let result = unsafe {
            let c_str = CStr::from_ptr(kdc_ptr);
            let rust_string = c_str.to_string_lossy().into_owned();
            libc::free(kdc_ptr as *mut libc::c_void);
            rust_string
        };

        Ok(result)
    }

    #[nasl_function]
    fn krb5_gss_init(&mut self) -> u32 {
        let mut cached_gss_context = self.cached_gss_context.lock().unwrap();
        *cached_gss_context = unsafe { okrb5_gss_init_context() };
        if cached_gss_context.is_null() {
            self.last_okrb5_result = OKrb5ErrorCode_O_KRB5_EXPECTED_NOT_NULL;
            OKrb5ErrorCode_O_KRB5_EXPECTED_NOT_NULL
        } else {
            self.last_okrb5_result = OKrb5ErrorCode_O_KRB5_SUCCESS;
            OKrb5ErrorCode_O_KRB5_SUCCESS
        }
    }

    #[nasl_function(named(config_path, realm, kdc, user, password, host, service))]
    fn krb5_gss_prepare_context(
        &mut self,
        config_path: Option<&str>,
        realm: Option<&str>,
        kdc: Option<&str>,
        user: Option<&str>,
        password: Option<&str>,
        host: Option<&str>,
        service: Option<&str>,
    ) -> Result<u32, FnError> {
        let credential =
            self.build_krb5_credential(config_path, realm, kdc, user, password, host, service)?;
        let mut cached_gss_context = self.cached_gss_context.lock().unwrap();
        if cached_gss_context.is_null() {
            *cached_gss_context = unsafe { okrb5_gss_init_context() };
            if cached_gss_context.is_null() {
                self.last_okrb5_result = OKrb5ErrorCode_O_KRB5_EXPECTED_NOT_NULL;
                return Err(Krb5Error::Context.into());
            }
        }

        self.last_okrb5_result = unsafe {
            o_krb5_gss_prepare_context(credential.okrb5_credential(), *cached_gss_context)
        };
        Ok(self.last_okrb5_result)
    }

    #[nasl_function]
    fn krb5_gss_update_context(&mut self, data: Option<StringOrData>) -> u32 {
        let data = data.map(|x| x.data()).unwrap_or_default();
        let data = OKrb5Slice {
            data: data.as_ptr() as *mut os::raw::c_void,
            len: data.len(),
        };
        let cached_gss_context = self.cached_gss_context.lock().unwrap();
        if cached_gss_context.is_null() {
            self.last_okrb5_result = OKrb5ErrorCode_O_KRB5_EXPECTED_NOT_NULL;
            return self.last_okrb5_result;
        }
        let mut to_application = self.to_application.lock().unwrap();

        if !to_application.is_null() {
            unsafe {
                let slice = &*(*to_application);
                if !slice.data.is_null() {
                    libc::free(slice.data);
                }
                libc::free(*to_application as *mut libc::c_void);
                *to_application = std::ptr::null_mut();
            }
        }

        let mut to_application_ptr = *to_application;
        let mut needs_more = false;
        self.last_okrb5_result = unsafe {
            o_krb5_gss_update_context(
                *cached_gss_context,
                &data,
                &mut to_application_ptr,
                &mut needs_more,
            )
        };
        *to_application = to_application_ptr;
        self.gss_context_needs_more = needs_more;
        self.last_okrb5_result
    }

    #[nasl_function]
    fn krb5_gss_update_context_out(&self) -> Option<String> {
        let to_application = self.to_application.lock().unwrap();
        if to_application.is_null() {
            return None;
        }
        let slice = unsafe { &*(*to_application) };
        if slice.data.is_null() {
            return None;
        }
        let bytes = unsafe { std::slice::from_raw_parts(slice.data as *const u8, slice.len) };
        let result = Some(String::from_utf8_lossy(bytes).into_owned());

        result
    }

    #[nasl_function]
    fn krb5_gss_update_context_needs_more(&self) -> bool {
        self.gss_context_needs_more
    }

    #[nasl_function]
    fn krb5_gss_session_key(&mut self) -> Option<String> {
        let cached_gss_context = self.cached_gss_context.lock().unwrap();
        if cached_gss_context.is_null() {
            self.last_okrb5_result = OKrb5ErrorCode_O_KRB5_EXPECTED_NOT_NULL;
            return None;
        }
        let mut session_key_slice: *mut OKrb5Slice = std::ptr::null_mut();
        self.last_okrb5_result =
            unsafe { o_krb5_gss_session_key_context(*cached_gss_context, &mut session_key_slice) };
        if !session_key_slice.is_null() {
            unsafe {
                let slice = &*session_key_slice;
                if !slice.data.is_null() {
                    let bytes = std::slice::from_raw_parts(slice.data as *const u8, slice.len);
                    let session_key = String::from_utf8_lossy(bytes).into_owned();
                    libc::free(slice.data);
                    libc::free(session_key_slice as *mut libc::c_void);
                    return Some(session_key);
                }
                libc::free(session_key_slice as *mut libc::c_void);
            }
        }
        None
    }
}

function_set! {
    Krb5,
    (
        (Krb5::krb5_is_failure, "krb5_is_failure"),
        (Krb5::krb5_is_success, "krb5_is_success"),
        (Krb5::krb5_error_code_to_string, "krb5_error_code_to_string"),
        (Krb5::krb5_find_kdc, "krb5_find_kdc"),
        (Krb5::krb5_gss_init, "krb5_gss_init"),
        (Krb5::krb5_gss_prepare_context, "krb5_gss_prepare_context"),
        (Krb5::krb5_gss_update_context, "krb5_gss_update_context"),
        (Krb5::krb5_gss_update_context_out, "krb5_gss_update_context_out"),
        (Krb5::krb5_gss_update_context_needs_more, "krb5_gss_update_context_needs_more"),
        (Krb5::krb5_gss_session_key, "krb5_gss_session_key"),
    )
}
