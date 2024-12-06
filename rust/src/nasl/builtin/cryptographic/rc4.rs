// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use rc4::Rc4;
use rc4::{consts::*, KeyInit, StreamCipher};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::nasl::prelude::*;

use super::{get_data, get_key, CryptographicError};

/// Structure to hold a Cipher Handler
pub struct CipherHandler {
    /// Handler ID
    pub id: i32,
    /// Handler
    pub handler: Rc4Key,
}

fn lock_handlers(
    handlers: &Arc<Mutex<Vec<CipherHandler>>>,
) -> Result<MutexGuard<Vec<CipherHandler>>, FnError> {
    // we actually need to panic as a lock error is fatal
    // alternatively we need to add a poison error on FnError
    Ok(Arc::as_ref(handlers).lock().unwrap())
}

fn get_new_cipher_id(handlers: &MutexGuard<Vec<CipherHandler>>) -> i32 {
    let mut new_val: i32 = 5000;
    if handlers.is_empty() {
        return new_val;
    }

    let mut list = handlers.iter().map(|x| x.id).collect::<Vec<i32>>();
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

#[derive(Default)]
pub struct CipherHandlers {
    cipher_handlers: Arc<Mutex<Vec<CipherHandler>>>,
}

impl CipherHandlers {
    /// Closes a stream cipher.
    #[nasl_function]
    pub fn close_stream_cipher(&self, register: &Register) -> Result<NaslValue, FnError> {
        let hd = match register.named("hd") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => return Err(CryptographicError::Rc4("Handler ID not found".to_string()).into()),
        };

        let mut handlers = lock_handlers(&self.cipher_handlers)?;
        match handlers.iter_mut().enumerate().find(|(_i, h)| h.id == hd) {
            Some((i, _h)) => {
                handlers.remove(i);
                Ok(NaslValue::Number(0))
            }
            _ => Err(CryptographicError::Rc4(format!("Handler ID {} not found", hd)).into()),
        }
    }

    /// Open RC4 cipher to encrypt a stream of data. The handler can be used to encrypt stream data.
    /// Opened cipher must be closed with (close_stream_cipher)[close_stream_cipher.md] when it is not used anymore.
    /// -iv: the initival vector
    /// -key: the key used for encryption
    ///  
    /// Returns the id of the encrypted data cipher handler on success.
    #[nasl_function]
    pub fn open_rc4_cipher(&self, register: &Register) -> Result<NaslValue, FnError> {
        // Get Arguments

        let key = match get_key(register) {
            Ok(k) if !k.is_empty() => k.to_vec(),
            _ => return Err(CryptographicError::Rc4("Missing Key argument".to_string()).into()),
        };

        let rc_handler = Rc4Key::build_handler_from_key(key.to_vec())?;
        let mut handlers = lock_handlers(&self.cipher_handlers)?;
        let id = get_new_cipher_id(&handlers);
        //let rc_handler =  Rc4::<Rc4Key>::new_from_slice(key).unwrap(); // new_from_slice(key).unwrap();

        let hd = CipherHandler {
            id,
            handler: rc_handler,
        };
        handlers.push(hd);
        Ok(NaslValue::Number(id as i64))
    }

    /// Encrypt data with a RC4 cipher.
    /// If a perviously opened (RC4 handler) exist the hd parameter should be set it will use
    /// the handler for encryption.
    /// If there is no open handler than the key and iv parameter must be set.
    ///  -data: string Data to decrypt
    ///  -hd: the handler index. (mandatory if not key and iv is given)
    ///  -iv: string Initialization vector (mandatory if no handler is given).
    ///  -key: string key (mandatory if no handler is given).
    #[nasl_function]
    pub fn rc4_encrypt(&self, register: &Register) -> Result<NaslValue, FnError> {
        let data = match get_data(register) {
            Ok(d) if !d.is_empty() => d.to_vec(),
            _ => return Err(CryptographicError::Rc4("Missing data argument".to_string()).into()),
        };

        let hd = match register.named("hd") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => 0,
        };

        let mut handlers = lock_handlers(&self.cipher_handlers)?;

        if hd > 0 {
            if let Some((_i, h)) = handlers.iter_mut().enumerate().find(|(_i, h)| h.id == hd) {
                let d = h.handler.encode(data);
                return Ok(NaslValue::Data(d));
            };
        };

        let key = match get_key(register) {
            Ok(k) if !k.is_empty() => k.to_vec(),
            _ => return Err(CryptographicError::Rc4("Missing Key argument".to_string()).into()),
        };

        let mut rc_handler = Rc4Key::build_handler_from_key(key.to_vec())?;
        let d = rc_handler.encode(data);
        Ok(NaslValue::Data(d))
    }
}

macro_rules! build_rc4key_enum {
    ($(($i:ident, $ty: ty, $l:literal),)*) => {
        pub enum Rc4Key {
            $(
                $i( Rc4<$ty>),
            )*
        }

        impl Rc4Key {
            fn build_handler_from_key(bl: Vec<u8>) -> Result<Self, FnError> {
                match bl.len() {
                    $($l => Ok(Self::$i(Rc4::new_from_slice(bl.as_slice()).unwrap())),)*
                    _ => {return Err(CryptographicError::Rc4("RC4 Key size not supported".into()).into())}
                }
            }

            fn encode (&mut self, data: Vec<u8>) -> Vec<u8> {
                match self {
                    $(Rc4Key::$i(e) =>{
                        let mut d = data.clone();
                        e.apply_keystream(&mut d);
                        d
                    })*
                }
            }
        }
    };
}

build_rc4key_enum! {
    (U1, U1, 1),
    (U2, U2, 2),
    (U3, U3, 3),
    (U4, U4, 4),
    (U5, U5, 5),
    (U6, U6, 6),
    (U7, U7, 7),
    (U8, U8, 8),
    (U9, U9, 9),
    (U10, U10, 10),
    (U11, U11, 11),
    (U12, U12, 12),
    (U13, U13, 13),
    (U14, U14, 14),
    (U15, U15, 15),
    (U16, U16, 16),
    (U17, U17, 17),
    (U18, U18, 18),
    (U19, U19, 19),
    (U20, U20, 20),
    (U21, U21, 21),
    (U22, U22, 22),
    (U23, U23, 23),
    (U24, U24, 24),
    (U25, U25, 25),
    (U26, U26, 26),
    (U27, U27, 27),
    (U28, U28, 28),
    (U29, U29, 29),
    (U30, U30, 30),
    (U31, U31, 31),
    (U32, U32, 32),
    (U33, U33, 33),
    (U34, U34, 34),
    (U35, U35, 35),
    (U36, U36, 36),
    (U37, U37, 37),
    (U38, U38, 38),
    (U39, U39, 39),
    (U40, U40, 40),
    (U41, U41, 41),
    (U42, U42, 42),
    (U43, U43, 43),
    (U44, U44, 44),
    (U45, U45, 45),
    (U46, U46, 46),
    (U47, U47, 47),
    (U48, U48, 48),
    (U49, U49, 49),
    (U50, U50, 50),
    (U51, U51, 51),
    (U52, U52, 52),
    (U53, U53, 53),
    (U54, U54, 54),
    (U55, U55, 55),
    (U56, U56, 56),
    (U57, U57, 57),
    (U58, U58, 58),
    (U59, U59, 59),
    (U60, U60, 60),
    (U61, U61, 61),
    (U62, U62, 62),
    (U63, U63, 63),
    (U64, U64, 64),
    (U70, U70, 70),
    (U80, U80, 80),
    (U90, U90, 90),
    (U100, U100, 100),
    (U200, U200, 200),
    (U300, U300, 300),
    (U400, U400, 400),
    (U500, U500, 500),
    (U128, U128, 128),
    (U256, U256, 256),
    (U512, U512, 512),
    (U1000, U1000, 1000),
    (U1024, U1024, 1024),
}

function_set! {
    CipherHandlers,
    (
        (CipherHandlers::close_stream_cipher, "close_stream_cipher"),
        (CipherHandlers::open_rc4_cipher, "open_rc4_cipher"),
        (CipherHandlers::rc4_encrypt, "rc4_encrypt")
    )
}
