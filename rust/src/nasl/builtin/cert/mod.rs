// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;
use std::sync::RwLock;

use nasl_function_proc_macro::nasl_function;
use thiserror::Error;
use x509_certificate::X509Certificate;
use x509_parser::prelude::GeneralName;

use crate::nasl::prelude::*;

use super::string::encode_hex;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("Unable to calculate SHA256 fingerprint")]
    UnableToCalculateSHA256Fingerprint,
    #[error("Unable to calculate SHA1 fingerprint")]
    UnableToCalculateSHA1Fingerprint,
    #[error("Query parameter 'all' not implemented yet.")]
    QueryParamAllNotImplemented,
}

fn sign_alg_oid_to_name(oid: &str) -> &str {
    match oid {
        "1.2.840.10040.4.1" => "id-dsa",
        "1.2.840.10046.2.1" => "dhpublicnumber",
        "2.16.840.1.101.2.1.1.22" => "id-keyExchangeAlgorithm",
        "1.2.840.10045.1.1" => "prime-field",
        "1.2.840.10045.2.1" => "id-ecPublicKey",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.132.1.12" => "id-ecDH",
        "1.2.840.10045.2.13" => "id-ecMQV",
        "1.2.840.113549.1.1.10" => "id-RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.14" => "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.8" => "id-mgf1",
        "1.2.840.113549.2.2" => "md2",
        "1.2.840.113549.2.4" => "md4",
        "1.2.840.113549.2.5" => "md5",
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.3" => "md4WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.6" => "rsaOAEPEncryptionSET",
        "1.2.840.10045.3.1.1" => "secp192r1",
        "1.3.132.0.1" => "sect163k1",
        "1.3.132.0.15" => "sect163r2",
        "1.3.132.0.33" => "secp224r1",
        "1.3.132.0.26" => "sect233k1",
        "1.3.132.0.27" => "sect233r1",
        "1.2.840.10045.3.1.7" => "secp256r1",
        "1.3.132.0.16" => "sect283k1",
        "1.3.132.0.17" => "sect283r1",
        "1.3.132.0.34" => "secp384r1",
        "1.3.132.0.36" => "sect409k1",
        "1.3.132.0.37" => "sect409r1",
        "1.3.132.0.35" => "sect521r1",
        "1.3.132.0.38" => "sect571k1",
        "1.3.132.0.39" => "sect571r1",
        "2.16.840.1.101.3.4.3.1" => "id-dsa-with-sha224",
        "2.16.840.1.101.3.4.3.2" => "id-dsa-with-sha256",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "2.16.840.1.101.3.4.2.4" => "sha224",
        _ => "unknown",
    }
}

fn pub_key_alg_oid_to_name(name: &str) -> &str {
    match name {
        "1.2.840.113549.1.1.1" => "RSA",
        "2.5.8.1.1" => "RSA (X.509)",
        "1.2.840.113549.1.1.4" => "RSA (MD5)",
        "1.2.840.113549.1.1.5" => "RSA (SHA1)",
        "1.2.840.10040.4.1" => "DSA",
        "1.2.643.2.2.19" => "GOST R 34.10-2001",
        "1.2.643.2.2.20" => "GOST R 34.10-94",
        "1.2.840.10045.2.1" => "EC",
        _ => "unknown",
    }
}

fn subject_oid_to_name(oid: &str) -> &str {
    match oid {
        "2.5.4.6" => "C",
        "2.5.4.8" => "ST",
        "2.5.4.7" => "L",
        "2.5.4.10" => "O",
        "2.5.4.3" => "CN",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "I",
        "2.5.4.4" => "SN",
        _ => oid,
    }
}

pub enum CertCommands {
    Serial,
    Issuer,
    Subject,
    NotBefore,
    NotAfter,
    All,
    Hostnames,
    FprSha256,
    FprSha1,
    Image,
    SignatureAlgorithmName,
    PublicKeyAlgorithmName,
    Modulus,
    Exponent,
    KeySize,
}

impl TryFrom<&str> for CertCommands {
    type Error = FnError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "serial" => Ok(Self::Serial),
            "issuer" => Ok(Self::Issuer),
            "subject" => Ok(Self::Subject),
            "not-before" => Ok(Self::NotBefore),
            "not-after" => Ok(Self::NotAfter),
            "all" => Ok(Self::All),
            "hostnames" => Ok(Self::Hostnames),
            "fpr-sha-256" => Ok(Self::FprSha256),
            "fpr-sha-1" => Ok(Self::FprSha1),
            "image" => Ok(Self::Image),
            "algorithm-name" => Ok(Self::SignatureAlgorithmName),
            "signature-algorithm-name" => Ok(Self::SignatureAlgorithmName),
            "public-key-algorithm-name" => Ok(Self::PublicKeyAlgorithmName),
            "modulus" => Ok(Self::Modulus),
            "exponent" => Ok(Self::Exponent),
            "key-size" => Ok(Self::KeySize),
            _ => Err(
                ArgumentError::WrongArgument("The given query is not valid.".to_string()).into(),
            ),
        }
    }
}

/// This structure holds a list of certificates. The entries of the list are
/// Optional to allow for the removal of certificates. The closed list holds
/// the indexes of the removed certificates.
#[derive(Default)]
struct Handles {
    certs: HashMap<usize, X509Certificate>,
    next: usize,
}

#[derive(Default)]
pub struct NaslCerts(RwLock<Handles>);

impl NaslCerts {
    fn insert(&self, cert: X509Certificate) -> usize {
        let mut handle = self.0.write().unwrap();
        let index = handle.next;
        handle.certs.insert(index, cert);
        handle.next += 1;
        handle.next - 1
    }

    /// Create a certificate object.
    ///
    /// Takes a string/data as unnamed argument and returns an identifier
    /// used with the other cert functions. The data is usually the BER
    /// encoded certificate but the function will also try a PEM encoding
    /// on failure to parse BER encoded one.
    ///
    /// On success the function returns a cert identifier that can be used
    /// for further operations.
    #[nasl_function]
    fn cert_open(&self, cert: &[u8]) -> Result<usize, FnError> {
        if let Ok(cert) = X509Certificate::from_der(cert) {
            return Ok(self.insert(cert));
        }
        if let Ok(cert) = X509Certificate::from_pem(cert) {
            return Ok(self.insert(cert));
        }
        if let Ok(cert) = X509Certificate::from_ber(cert) {
            return Ok(self.insert(cert));
        }

        Err(ArgumentError::WrongArgument(
            "The given string is not a valid DER, BER or PEM encoded X.509 certificate."
                .to_string(),
        )
        .into())
    }

    /// Release a certificate object.
    ///
    /// Takes a cert identifier as returned by cert_open and releases the
    /// associated resources.
    #[nasl_function]
    fn cert_close(&self, cert_handle: usize) {
        let mut handle = self.0.write().unwrap();
        handle.certs.remove(&cert_handle);
    }

    fn subject(cert: &X509Certificate, idx: usize) -> Option<String> {
        // The error originates from the io::Write trait. Internally a Vec is used, which
        // implementation of that trait is infallible. Therefore we can unwrap here.
        let der = cert.encode_der().unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

        if idx == 0 {
            Some(cert.subject.to_string())
        } else {
            cert.subject_alternative_name()
                .ok()
                .flatten()
                .and_then(|san| san.value.general_names.get(idx - 1))
                .map(|san| Some(san.to_string()))
                .unwrap_or(None)
        }
    }

    fn issuer(cert: &X509Certificate, idx: usize) -> Option<String> {
        let subject = cert.issuer_name();
        subject.get(idx).map(|entry| {
            entry
                .iter()
                .filter_map(|val| {
                    val.value.to_string().ok().map(|value| {
                        format!("{}={}", subject_oid_to_name(&val.typ.to_string()), value)
                    })
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
    }

    fn hostnames(cert: &X509Certificate) -> Vec<String> {
        let mut ret = vec![];
        if let Some(cn) = cert.subject_common_name() {
            ret.push(cn);
        }

        let der = cert.encode_der().unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in san.value.general_names.iter() {
                if let GeneralName::DNSName(dns) = name {
                    ret.push(dns.to_string());
                }
            }
        }

        ret
    }

    fn key_size(cert: &X509Certificate) -> Option<i64> {
        let algorithm = cert.key_algorithm()?;
        match algorithm {
            x509_certificate::KeyAlgorithm::Rsa => {
                if let Ok(data) = cert.rsa_public_key_data() {
                    return Some(((data.modulus.into_bytes().len() - 1) * 8) as i64);
                }
            }
            _ => {
                if let Ok(data) = cert.rsa_public_key_data() {
                    return Some((data.public_exponent.into_bytes().len() * 8) as i64);
                }
            }
        }
        None
    }

    /// Query a certificate object.
    ///
    /// Takes a cert identifier as first unnamed argument and a command
    /// string as second argument. That command is used to select specific
    /// information from the certificate. For certain commands the named
    /// argument @a idx is used as well. Depending on this command the
    /// return value may be a number, a string, or an array of strings.
    /// Supported commands are:
    ///
    /// - serial The serial number of the certificate as a hex string.
    ///
    /// - issuer Returns the issuer.  The returned value is a string in
    ///             rfc-2253 format.
    ///
    /// - subject Returns the subject. The returned value is a string in
    ///              rfc-2253 format.  To query the subjectAltName the
    ///              named parameters @a idx with values starting at 1 can
    ///              be used. In this case the format is either an rfc2253
    ///              string as used above, an rfc2822 mailbox name
    ///              indicated by the first character being a left angle
    ///              bracket or an S-expression in advanced format for all
    ///              other types of subjectAltnames which is indicated by
    ///              an opening parentheses.
    ///
    /// - not-before The notBefore time as UTC value in ISO time format
    ///                 (e.g. "20120930T143521").
    ///
    /// - not-after  The notAfter time as UTC value in ISO time format
    ///                 (e.g. "20280929T143520").
    ///
    /// - all Return all available information in a human readable
    ///          format.  Not yet implemented.
    ///
    /// - hostnames Return an array with all hostnames listed in the
    ///   certificates, i.e. the CN part of the subject and all dns-name
    ///   type subjectAltNames.
    ///
    /// - fpr-sha-256 The SHA-256 fingerprint of the certificate.  The
    ///                  fingerprint is, as usual, computed over the entire
    ///                  DER encode certificate.
    ///
    /// - fpr-sha-1   The SHA-1 fingerprint of the certificate.  The
    ///                  fingerprint is, as usual, computed over the entire
    ///                  DER encode certificate.
    ///
    /// - image       Return the entire certificate as binary data.
    ///
    /// - algorithm-name  Same as signature-algorithm-name. TODO: Remove it and
    ///                      leave only signature-algorithm-name.
    ///
    /// - signature-algorithm-name  Return the algorithm name used to sign the
    ///                                certificate. Get the OID of the digest
    ///                                algorithm and translated to a name from a
    ///                                list from Wireshark.
    ///                                See epan/dissectors/packet-pkcs1.c
    ///
    /// - public-key-algorithm-name  Return the algorithm name of the public key.
    ///
    /// - modulus      Return the RSA public key's modulus found in the
    ///                   structure of the given cert.
    ///
    /// - exponent    Return the RSA public key's exponent found in
    ///                  the structure of the given cert.
    ///
    /// - key-size    Return the size to hold the parameters size in bits.
    ///                  For RSA the bits returned is the modulus.
    ///                  For DSA the bits returned are of the public exponent.
    ///
    ///
    /// The following arguments are required:
    /// - pos(0): Object id of the certificate.
    ///
    /// - pos(1): A string with the command to select what to return; see above.
    ///
    /// The following arguments are optional:
    /// - idx Used by certain commands to select the n-th value of a set
    ///    of values.  If not given 0 is assumed.
    ///
    /// A NASL type depending on the used command.
    #[nasl_function(named(idx))]
    fn cert_query(
        &self,
        cert_handle: usize,
        query: &str,
        idx: Option<usize>,
    ) -> Result<NaslValue, FnError> {
        let idx = idx.unwrap_or(0);
        let handle = self.0.read().unwrap();

        let cert = handle.certs.get(&cert_handle).ok_or_else(|| {
            ArgumentError::WrongArgument("The given file descriptor is not valid.".to_string())
        })?;
        let result = match CertCommands::try_from(query)? {
            CertCommands::Serial => {
                let serial = cert.serial_number_asn1().clone().into_bytes();
                NaslValue::String(encode_hex(&serial))
            }
            CertCommands::Subject => Self::subject(cert, idx)
                .map(NaslValue::String)
                .unwrap_or(NaslValue::Null),
            CertCommands::Issuer => Self::issuer(cert, idx)
                .map(NaslValue::String)
                .unwrap_or(NaslValue::Null),
            CertCommands::NotBefore => {
                let not_before = cert.validity_not_before().format("%Y%m%dT%H%M%S");
                NaslValue::String(not_before.to_string())
            }
            CertCommands::NotAfter => {
                let not_after = cert.validity_not_after().format("%Y%m%dT%H%M%S");
                NaslValue::String(not_after.to_string())
            }
            CertCommands::FprSha256 => cert
                .sha256_fingerprint()
                .map(|fpr| NaslValue::String(encode_hex(fpr.as_ref())))
                .map_err(|_| CertError::UnableToCalculateSHA256Fingerprint)?,
            CertCommands::FprSha1 => cert
                .sha1_fingerprint()
                .map(|fpr| NaslValue::String(encode_hex(fpr.as_ref())))
                .map_err(|_| CertError::UnableToCalculateSHA1Fingerprint)?,
            CertCommands::All => return Err(CertError::QueryParamAllNotImplemented.into()),
            CertCommands::Hostnames => NaslValue::Array(
                Self::hostnames(cert)
                    .into_iter()
                    .map(NaslValue::String)
                    .collect::<Vec<NaslValue>>(),
            ),
            CertCommands::Image => NaslValue::Data(cert.encode_der().unwrap_or_default()),
            CertCommands::SignatureAlgorithmName => {
                let signature_algorithm_oid = cert.signature_algorithm_oid().to_string();
                let signature_algorithm = sign_alg_oid_to_name(&signature_algorithm_oid);
                NaslValue::String(signature_algorithm.to_string())
            }
            CertCommands::PublicKeyAlgorithmName => {
                let key_algorithm_oid = cert.key_algorithm_oid().to_string();
                let public_key_algorithm = pub_key_alg_oid_to_name(&key_algorithm_oid);
                NaslValue::String(public_key_algorithm.to_string())
            }
            CertCommands::Modulus => cert
                .rsa_public_key_data()
                .map(|data| NaslValue::Data(data.modulus.into_bytes().to_vec()))
                .unwrap_or(NaslValue::Null),
            CertCommands::Exponent => cert
                .rsa_public_key_data()
                .map(|data| NaslValue::Data(data.public_exponent.into_bytes().to_vec()))
                .unwrap_or(NaslValue::Null),
            CertCommands::KeySize => Self::key_size(cert)
                .map(NaslValue::Number)
                .unwrap_or(NaslValue::Null),
        };
        Ok(result)
    }
}

function_set! {
    NaslCerts,
    (
        (NaslCerts::cert_open, "cert_open"),
        (NaslCerts::cert_close, "cert_close"),
        (NaslCerts::cert_query, "cert_query"),
    )
}
