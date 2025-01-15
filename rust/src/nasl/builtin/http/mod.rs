// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL functions to perform HTTP/2 request.
// TODO: implement http functions once socket handling is available

mod error;

use crate::nasl::prelude::*;
use crate::nasl::utils::ContextType;

pub use error::HttpError;
use h2::client;

use core::convert::AsRef;
use http::{response::Parts, Method, Request};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use std::sync::Arc;

use rustls::ClientConfig;
use tokio::{
    net::TcpStream,
    sync::{Mutex, MutexGuard},
};
use tokio_rustls::TlsConnector;

pub struct Handle {
    pub handle_id: i32,
    pub header_items: Vec<(String, String)>,
    pub http_code: u16,
}

#[derive(Default)]
pub struct NaslHttp {
    handles: Arc<Mutex<Vec<Handle>>>,
}

async fn lock_handles(
    handles: &Arc<Mutex<Vec<Handle>>>,
) -> Result<MutexGuard<Vec<Handle>>, FnError> {
    // we actually need to panic as a lock error is fatal
    // alternatively we need to add a poison error on FnError
    Ok(Arc::as_ref(handles).lock().await)
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
    ) -> Result<(Parts, String), HttpError> {
        // Establish TCP connection to the server.

        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        // For HTTP/2. For older HTTP versions should not be set,
        config.alpn_protocols = vec![b"h2".to_vec()];

        let server_name = ip_str.clone().to_owned().try_into().unwrap();

        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(format!("{}:{}", ip_str, port))
            .await
            .map_err(HttpError::from)?;
        let stream = connector
            .connect(server_name, stream)
            .await
            .map_err(HttpError::from)?;
        let (h2, connection) = client::handshake(stream).await.map_err(HttpError::from)?;

        tokio::spawn(async move {
            connection.await.unwrap();
        });

        let mut h2 = h2.ready().await.map_err(HttpError::from)?;

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
            let chunk = chunk.map_err(HttpError::from)?;

            resp.push_str(&String::from_utf8_lossy(&chunk));
            // Let the server send more data.
            let _ = flow_control.release_capacity(chunk.len());
        }

        Ok((head, resp))
    }

    /// Perform request with the given method.
    async fn http2_req(
        &self,
        register: &Register,
        ctx: &Context<'_>,
        method: Method,
    ) -> Result<NaslValue, FnError> {
        let handle_id = match register.named("handle") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => return Err(ArgumentError::WrongArgument("Invalid handle ID".to_string()).into()),
        };

        let mut handles = lock_handles(&self.handles).await?;
        let (_, handle) = handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle_id)
            .ok_or(HttpError::HandleIdNotFound(handle_id))?;

        let item: String = register
            .named("item")
            .map(|x| x.to_string())
            .ok_or(FnError::missing_argument("item"))?;

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

        let (head, body) = self
            .request(&ip_str, port, uri, data, method, handle)
            .await?;
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

    /// Wrapper function for GET request. See http2_req
    #[nasl_function]
    async fn get(&self, register: &Register, ctx: &Context<'_>) -> Result<NaslValue, FnError> {
        self.http2_req(register, ctx, Method::GET).await
    }

    /// Wrapper function for POST request. See http2_req
    #[nasl_function]
    async fn post(&self, register: &Register, ctx: &Context<'_>) -> Result<NaslValue, FnError> {
        self.http2_req(register, ctx, Method::POST).await
    }

    /// Wrapper function for PUT request. See http2_req
    #[nasl_function]
    async fn put(&self, register: &Register, ctx: &Context<'_>) -> Result<NaslValue, FnError> {
        self.http2_req(register, ctx, Method::PUT).await
    }

    /// Wrapper function for HEAD request. See http2_req
    #[nasl_function]
    async fn head(&self, register: &Register, ctx: &Context<'_>) -> Result<NaslValue, FnError> {
        self.http2_req(register, ctx, Method::HEAD).await
    }

    /// Wrapper function for DELETE request. See http2_req
    #[nasl_function]
    async fn delete(&self, register: &Register, ctx: &Context<'_>) -> Result<NaslValue, FnError> {
        self.http2_req(register, ctx, Method::DELETE).await
    }

    /// Creates a handle for http requests
    /// nasl params
    ///   - Handle identifier. Null on error.
    ///
    /// On success the function returns a and integer with the handle
    /// identifier. Null on error.
    #[nasl_function]
    async fn handle(&self) -> Result<NaslValue, FnError> {
        let mut handles = lock_handles(&self.handles).await?;
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
    #[nasl_function(named(handle))]
    async fn close_handle(&self, handle: i32) -> Result<NaslValue, FnError> {
        let mut handles = lock_handles(&self.handles).await?;
        match handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle)
        {
            Some((i, _h)) => {
                handles.remove(i);
                Ok(NaslValue::Number(0))
            }
            _ => Err(HttpError::HandleIdNotFound(handle).with(ReturnValue(-1))),
        }
    }

    /// Get the http response code after performing a HTTP request.
    /// nasl named param
    ///   - handle The handle identifier
    ///
    /// On success the function returns an integer
    /// representing the http code response. Null on error.
    #[nasl_function]
    async fn get_response_code(&self, register: &Register) -> Result<NaslValue, FnError> {
        let handle_id = match register.named("handle") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => {
                return Err(ArgumentError::WrongArgument(("Invalid handle ID").to_string()).into())
            }
        };

        let mut handles = lock_handles(&self.handles).await?;
        match handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle_id)
        {
            Some((_i, handle)) => Ok(NaslValue::Number(handle.http_code as i64)),
            _ => Err(HttpError::HandleIdNotFound(handle_id).into()),
        }
    }

    /// Set a custom header element in the header
    /// nasl named param
    ///   - handle The handle identifier
    ///   - header_item A string to add to the header
    ///
    /// On success the function returns an integer. 0 on success. Null on error.
    #[nasl_function]
    async fn set_custom_header(&self, register: &Register) -> Result<NaslValue, FnError> {
        let header_item = match register.named("header_item") {
            Some(ContextType::Value(NaslValue::String(x))) => x,
            _ => return Err(FnError::missing_argument("No command passed")),
        };

        let (key, val) = header_item.split_once(": ").expect("Missing header_item");

        let handle_id = match register.named("handle") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => {
                return Err(ArgumentError::WrongArgument(("Invalid handle ID").to_string()).into())
            }
        };

        let mut handles = lock_handles(&self.handles).await?;
        match handles
            .iter_mut()
            .enumerate()
            .find(|(_i, h)| h.handle_id == handle_id)
        {
            Some((_i, h)) => {
                h.header_items.push((key.to_string(), val.to_string()));
                Ok(NaslValue::Number(0))
            }
            _ => Err(HttpError::HandleIdNotFound(handle_id).into()),
        }
    }
}

function_set! {
    NaslHttp,
    (
        (NaslHttp::handle, "http2_handle"),
        (NaslHttp::close_handle, "http2_close_handle"),
        (NaslHttp::get_response_code, "http2_get_response_code"),
        (NaslHttp::set_custom_header, "http2_set_custom_header"),
        (NaslHttp::get, "http2_get"),
        (NaslHttp::head, "http2_head"),
        (NaslHttp::post, "http2_post"),
        (NaslHttp::delete, "http2_delete"),
        (NaslHttp::put, "http2_put"),
    )
}
