// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL functions to perform HTTP/2 request.
// TODO: implement http functions once socket handling is available

use nasl_builtin_utils::{Context, ContextType, FunctionErrorKind, Register};
use nasl_syntax::NaslValue;

use h2::client;

use core::convert::AsRef;
use http::{response::Parts, Method, Request};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use std::sync::{Arc, Mutex, MutexGuard};

use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type NaslHttp2Function<K> =
    fn(&NaslHttp, &Register, &Context<K>) -> Result<NaslValue, FunctionErrorKind>;

pub struct Handle {
    pub handle_id: i32,
    pub header_items: Vec<(String, String)>,
    pub http_code: u16,
}

#[derive(Default)]
pub struct NaslHttp {
    handles: Arc<Mutex<Vec<Handle>>>,
}

fn lock_handles(
    handles: &Arc<Mutex<Vec<Handle>>>,
) -> Result<MutexGuard<Vec<Handle>>, FunctionErrorKind> {
    // we actually need to panic as a lock error is fatal
    // alternatively we need to add a poison error on FunctionErrorKind
    Ok(Arc::as_ref(handles).lock().unwrap())
}

/// Return the next available handle ID
fn next_handle_id(handles: &MutexGuard<Vec<Handle>>) -> i32 {
    // Note that the first handle ID we will
    // hand out is an arbitrary high number, this is only to help
    // debugging.
    let mut new_val: i32 = 9000;
    if handles.is_empty() {
        return new_val;
    }

    let mut list = handles.iter().map(|x| x.handle_id).collect::<Vec<i32>>();
    list.sort();

    for (i, v) in list.iter().enumerate() {
        if i == list.len() - 1 {
            new_val = v + 1;
            break;
        }
        if new_val != list[i] {
            break;
        }

        new_val += 1;
    }
    new_val
}

/// NoVerifier is to allow insecure connections
#[derive(Debug)]
pub struct NoVerifier;

/// DANGER: This custom implementation of the SeverCertVerifier
/// is really dangerous and return success for all and everything.
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

impl NaslHttp {
    async fn request(
        &self,
        ip_str: &String,
        port: u16,
        uri: String,
        data: String,
        method: Method,
        handle: &mut Handle,
    ) -> Result<(Parts, String), FunctionErrorKind> {
        // Establish TCP connection to the server.

        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        // For HTTP/2. For older HTTP versions should not be set,
        config.alpn_protocols = vec![b"h2".to_vec()];

        let server_name = ip_str.clone().to_owned().try_into().unwrap();

        let connector = TlsConnector::from(Arc::new(config));
        let stream = match TcpStream::connect(format!("{}:{}", ip_str, port)).await {
            Ok(a) => a,
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    e.to_string(),
                    Some(NaslValue::Null),
                ));
            }
        };

        let stream = match connector.connect(server_name, stream).await {
            Ok(a) => a,
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    e.to_string(),
                    Some(NaslValue::Null),
                ));
            }
        };

        let (h2, connection) = match client::handshake(stream).await {
            Ok((x, y)) => (x, y),
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    e.to_string(),
                    Some(NaslValue::Null),
                ))
            }
        };

        tokio::spawn(async move {
            connection.await.unwrap();
        });

        let mut h2 = match h2.ready().await {
            Ok(x) => x,
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    e.to_string(),
                    Some(NaslValue::Null),
                ))
            }
        };

        // Prepare the HTTP request to send to the server.
        let mut request = Request::builder();

        // add custom headers
        for (k, v) in handle.header_items.iter() {
            request = request.header(k, v);
        }
        let request = request.method(method).uri(uri).body(()).unwrap();

        // Send the request. The second tuple item allows the caller
        // to stream a request body.
        let (response, mut send_stream) = h2.send_request(request, false).unwrap();
        send_stream.send_data(data.into(), true).unwrap();
        let (head, mut body) = response.await.expect("some response").into_parts();

        // The `flow_control` handle allows the caller to manage
        // flow control.
        //
        // Whenever data is received, the caller is responsible for
        // releasing capacity back to the server once it has freed
        // the data from memory.
        let mut flow_control = body.flow_control().clone();

        let mut resp = String::new();
        while let Some(chunk) = body.data().await {
            let chunk = match chunk {
                Ok(byte_chunk) => byte_chunk,
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        e.to_string(),
                        Some(NaslValue::Null),
                    ))
                }
            };

            resp.push_str(&String::from_utf8_lossy(&chunk));
            // Let the server send more data.
            let _ = flow_control.release_capacity(chunk.len());
        }

        Ok((head, resp))
    }

    /// Perform request with the given method.
    fn http2_req<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
        method: Method,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let handle_id = match register.named("handle") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid handle ID").to_string(),
                ))
            }
        };

        let mut handles = lock_handles(&self.handles)?;
        let handle = match handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle_id)
        {
            Some((_i, handle)) => handle,
            _ => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!("Handle ID {} not found", handle_id),
                    Some(NaslValue::Null),
                ))
            }
        };

        let item: String = match register.named("item") {
            Some(x) => x.to_string(),
            _ => {
                return Err(FunctionErrorKind::Diagnostic(
                    "Missing item".to_string(),
                    Some(NaslValue::Null),
                ))
            }
        };

        let schema: String = match register.named("schema") {
            Some(x) => {
                if x.to_string() == *"http" || x.to_string() == *"https" {
                    x.to_string()
                } else {
                    "https".to_string()
                }
            }
            _ => "https".to_string(),
        };

        let data: String = match register.named("data") {
            Some(x) => x.to_string(),
            _ => String::new(),
        };

        let port = match register.named("port") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
            _ => 0u16,
        };

        let ip_str: String = match ctx.target() {
            x if !x.is_empty() => x.to_string(),
            _ => "127.0.0.1".to_string(),
        };

        let mut uri: String;
        if port != 80 && port != 443 {
            uri = format!("{}://{}:{}", schema, ip_str, port);
        } else {
            uri = format!("{}://{}", schema, ip_str)
        }

        uri = format!("{}{}", uri, item);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        match runtime.block_on(self.request(&ip_str, port, uri, data, method, handle)) {
            Ok((head, body)) => {
                handle.http_code = head.status.as_u16();
                let mut header_str = String::new();
                header_str.push_str(format!("{:?} ", head.version).as_str());
                header_str.push_str(format!("{:?}\n", head.status).as_str());
                for (k, v) in head.headers.iter() {
                    header_str.push_str(&format!(
                        "{}: {}\n",
                        k.as_str(),
                        String::from_utf8_lossy(v.as_bytes())
                    ))
                }
                //let _ = head.headers.iter().map(|(k,v)| header_str.push_str(&format!("{}: {}\n", k.as_str(), String::from_utf8_lossy(v.as_bytes()))));
                header_str.push_str(&body);
                Ok(NaslValue::String(header_str))
            }
            Err(e) => Err(e),
        }
    }

    /// Wrapper function for GET request. See http2_req
    fn get<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.http2_req(register, ctx, Method::GET)
    }

    /// Wrapper function for POST request. See http2_req
    fn post<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.http2_req(register, ctx, Method::POST)
    }

    /// Wrapper function for PUT request. See http2_req
    fn put<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.http2_req(register, ctx, Method::PUT)
    }

    /// Wrapper function for HEAD request. See http2_req
    fn head<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.http2_req(register, ctx, Method::HEAD)
    }

    /// Wrapper function for DELETE request. See http2_req
    fn delete<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.http2_req(register, ctx, Method::DELETE)
    }

    /// Creates a handle for http requests
    /// nasl params
    ///   - Handle identifier. Null on error.
    ///
    /// On success the function returns a and integer with the handle
    /// identifier. Null on error.
    fn handle<K>(
        &self,
        _register: &Register,
        _: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let mut handles = lock_handles(&self.handles)?;
        let handle_id = next_handle_id(&handles);
        let h = Handle {
            handle_id,
            header_items: Vec::default(),
            http_code: 0,
        };
        handles.push(h);

        Ok(NaslValue::Number(handle_id as i64))
    }

    /// Close a handle for http requests previously initialized
    /// nasl named param
    ///   - handle The handle identifier for the handle to be closed
    ///
    /// The function returns an integer.
    /// O on success, -1 on error.
    fn close_handle<K>(
        &self,
        register: &Register,
        _: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        };

        let handle_id = match &positional[0] {
            NaslValue::Number(handle_id) => *handle_id as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid handle ID").to_string(),
                ))
            }
        };

        let mut handles = lock_handles(&self.handles)?;
        match handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle_id)
        {
            Some((i, _h)) => {
                handles.remove(i);
                Ok(NaslValue::Number(0))
            }
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Handle ID {} not found", handle_id),
                Some(NaslValue::Number(-1)),
            )),
        }
    }

    /// Get the http response code after performing a HTTP request.
    /// nasl named param
    ///   - handle The handle identifier
    ///
    /// On success the function returns an integer
    /// representing the http code response. Null on error.
    fn get_response_code<K>(
        &self,
        register: &Register,
        _: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let handle_id = match register.named("handle") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid handle ID").to_string(),
                ))
            }
        };

        let mut handles = lock_handles(&self.handles)?;
        match handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle_id)
        {
            Some((_i, handle)) => Ok(NaslValue::Number(handle.http_code as i64)),
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Handle ID {} not found", handle_id),
                Some(NaslValue::Null),
            )),
        }
    }

    /// Set a custom header element in the header
    /// nasl named param
    ///   - handle The handle identifier
    ///   - header_item A string to add to the header
    /// On success the function returns an integer. 0 on success. Null on error.
    fn set_custom_header<K>(
        &self,
        register: &Register,
        _: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let header_item = match register.named("header_item") {
            Some(ContextType::Value(NaslValue::String(x))) => x,
            _ => return Err(FunctionErrorKind::from("No command passed")),
        };

        let (key, val) = header_item.split_once(": ").expect("Missing header_item");

        let handle_id = match register.named("handle") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid handle ID").to_string(),
                ))
            }
        };

        let mut handles = lock_handles(&self.handles)?;
        match handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle_id)
        {
            Some((_i, h)) => {
                h.header_items.push((key.to_string(), val.to_string()));
                Ok(NaslValue::Number(0))
            }
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Handle ID {} not found", handle_id),
                Some(NaslValue::Null),
            )),
        }
    }

    /// Returns found function for key or None when not found
    fn lookup<K>(key: &str) -> Option<NaslHttp2Function<K>> {
        match key {
            "http2_handle" => Some(NaslHttp::handle),
            "http2_close_handle" => Some(NaslHttp::close_handle),
            "http2_get_response_code" => Some(NaslHttp::get_response_code),
            "http2_set_custom_header" => Some(NaslHttp::set_custom_header),
            "http2_get" => Some(NaslHttp::get),
            "http2_head" => Some(NaslHttp::head),
            "http2_post" => Some(NaslHttp::post),
            "http2_delete" => Some(NaslHttp::delete),
            "http2_put" => Some(NaslHttp::put),
            _ => None,
        }
    }
}

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for NaslHttp {
    fn nasl_fn_cache_clear(&self) -> Option<usize> {
        let mut data = Arc::as_ref(&self.handles).lock().unwrap();
        if data.is_empty() {
            return None;
        }
        let result = data.len();
        data.clear();
        data.shrink_to_fit();
        Some(result)
    }

    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        NaslHttp::lookup(name).map(|x| x(self, register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        NaslHttp::lookup::<K>(name).is_some()
    }
}
