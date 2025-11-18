// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use digest::typenum;
use md5::Digest;
use rand::Rng;

use crate::nasl::{builtin::cryptographic::hmac::hmac, prelude::*, utils::function::StringOrData};

const NTLMSSP_NEGOTIATE_LM_KEY: i64 = 0x00000080;

/// SMB/NTLM algorithm to convert a 7-byte slice into an 8-byte DES key.
fn key7_to_key8(key7: &[u8]) -> Vec<u8> {
    let mut key7 = key7.to_vec();
    key7.resize(7, 0);

    let mut key8 = vec![0u8; 8];
    key8[0] = key7[0] >> 1;
    key8[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2);
    key8[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3);
    key8[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4);
    key8[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5);
    key8[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6);
    key8[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7);
    key8[7] = key7[6] & 0x7F;
    for item in key8.iter_mut() {
        *item <<= 1;
    }
    key8
}

/// Encrypts data using DES with a 7-byte key, expanding it to an 8-byte key.
fn smb_des_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    use des::Des;
    use digest::KeyInit;
    use ecb::cipher::BlockEncrypt;
    use ecb::cipher::generic_array::GenericArray;
    // Expand 7-byte key to 8-byte DES key
    let key8 = key7_to_key8(key);
    let cipher = Des::new(&GenericArray::clone_from_slice(&key8));
    let mut data = data.to_vec();
    data.resize(8, 0);
    let mut data = GenericArray::clone_from_slice(&data);
    cipher.encrypt_block(&mut data);

    data.to_vec()
}

/// Converts a 14-byte key into a 16-byte key for NTLMv1.
fn ep16(key14: &[u8]) -> Vec<u8> {
    let mut key = key14.to_vec();
    key.resize(14, 0);
    let sp8: [u8; 8] = [0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25];
    let mut result1 = smb_des_encrypt(&sp8, &key[..7]);
    let mut result2 = smb_des_encrypt(&sp8, &key[7..]);
    result1.append(&mut result2);
    result1
}

/// Converts a 21-byte key into a 24-byte key for NTLMv2.
fn ep24(data: &[u8], key21: &[u8]) -> Vec<u8> {
    let mut key = key21.to_vec();
    key.resize(21, 0);
    let mut result1 = smb_des_encrypt(data, &key[..7]);
    let mut result2 = smb_des_encrypt(data, &key[7..14]);
    let mut result3 = smb_des_encrypt(data, &key[14..]);
    result1.append(&mut result2);
    result1.append(&mut result3);
    result1
}

/// Computes the SAM OEM hash for NTLMv1.
/// This is a simplified version that uses RC4 to encrypt the data with the key.
fn sam_oem_hash(data: &[u8], key: &[u8]) -> Vec<u8> {
    use rc4::cipher::generic_array::GenericArray;
    use rc4::{KeyInit, Rc4, StreamCipher};

    let mut key = key.to_vec();
    key.resize(16, 0);
    let mut rc4 = Rc4::new(GenericArray::<u8, typenum::U16>::from_slice(&key));
    let mut data = data.to_vec();
    data.resize(16, 0);
    rc4.apply_keystream(&mut data);
    data
}

/// Generates the NTLMv1 session key from the NT hash.
/// This function pads the NT hash to 16 bytes and computes the MD4 hash.
fn smb_session_keygen_ntv1_ntlmssp(nthash: &[u8]) -> Vec<u8> {
    use md4::{Digest, Md4};

    let mut nthash = nthash.to_vec();
    nthash.resize(16, 0);
    let mut hasher = Md4::new();
    hasher.update(nthash);
    hasher.finalize().to_vec()
}

fn smb_encrypt_hash_ntlmssp(password: &[u8], challenge_data: &[u8]) -> Vec<u8> {
    let mut password = password.to_vec();
    password.resize(16, 0);
    password.resize(21, 0);
    ep24(challenge_data, &password)
}

fn smb_lm_session_keygen_ntlmssp(lm_hash: &[u8], lm_response: &[u8]) -> Vec<u8> {
    let mut partial_lm_hash = lm_hash.to_vec();
    partial_lm_hash.resize(8, 0);
    partial_lm_hash.resize(16, 0xbd);
    let mut hash = smb_encrypt_hash_ntlmssp(&partial_lm_hash, lm_response);
    hash.resize(16, 0);
    hash
}

fn e_des_hash_ntlmssp(password: &str) -> (Vec<u8>, bool) {
    let password = password.to_uppercase();
    let p16 = ep16(password.as_bytes());
    (p16, password.len() <= 14)
}

fn smb_session_keygen_ntv2_ntlmssp(key: &[u8], nt_response: &[u8]) -> Vec<u8> {
    use md5::Md5;
    let mut key = key.to_vec();
    key.resize(16, 0);
    // We can unwrap here, as the key is always 16 bytes.
    hmac::<Md5>(&key, nt_response).unwrap()
}

fn smb_owf_encrypt_ntv2_ntlmssp(
    key: &[u8],
    server_challenge_data: &[u8],
    client_challenge_data: &[u8],
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use md5::Md5;

    let mut key = key.to_vec();
    key.resize(16, 0);

    // We can unwrap here, as the key is always 16 bytes.
    let mut hmac = Hmac::<Md5>::new_from_slice(&key).unwrap();
    hmac.update(server_challenge_data);
    hmac.update(client_challenge_data);
    hmac.finalize().into_bytes().to_vec()
}

fn ntlmv2_generate_client_data_ntlmssp(addr_list: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    /*length of response
     *header-4, reserved-4, date-8, client chal-8, unknown-4, addr_list-size sent
     *in arguments
     */
    let mut response = vec![];
    let header: [u8; 4] = [0x00, 0x00, 0x01, 0x01];
    let zeros: [u8; 4] = [0x00; 4];
    let now = nt_time::FileTime::now().to_ne_bytes();
    let client_chal: [u8; 8] = rng.random();

    response.extend_from_slice(&header);
    response.extend_from_slice(&zeros);
    response.extend_from_slice(&now);
    response.extend_from_slice(&client_chal);
    response.extend_from_slice(&zeros);
    response.extend_from_slice(addr_list);

    response
}

fn ntlmv2_generate_response_ntlmssp(
    ntlmv2_hash: &[u8],
    server_chal: &[u8],
    addr_list: &[u8],
    rng: &mut impl Rng,
) -> Vec<u8> {
    let mut client_data = ntlmv2_generate_client_data_ntlmssp(addr_list, rng);
    let mut response = smb_owf_encrypt_ntv2_ntlmssp(ntlmv2_hash, server_chal, &client_data);
    response.append(&mut client_data);
    response
}

fn lmv2_generate_response_ntlmssp(ntlm_v2_hash: &[u8], server_chal: &[u8]) -> Vec<u8> {
    let lmv2_client_data: [u8; 8] = rand::rng().random();
    let mut response = smb_owf_encrypt_ntv2_ntlmssp(ntlm_v2_hash, server_chal, &lmv2_client_data);
    response.extend_from_slice(&lmv2_client_data);
    response
}

fn smb_ntlmv2_encrypt_hash_ntlmssp(
    ntlmv2_hash: &[u8],
    server_chal: &[u8],
    address_list: &[u8],
    rng: &mut impl Rng,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let nt_response = ntlmv2_generate_response_ntlmssp(ntlmv2_hash, server_chal, address_list, rng);
    let user_session_key = smb_session_keygen_ntv2_ntlmssp(ntlmv2_hash, &nt_response);
    let lm_response = lmv2_generate_response_ntlmssp(ntlmv2_hash, server_chal);

    (lm_response, nt_response, user_session_key)
}

fn ntlmssp_genauth_ntlm(
    password: &str,
    challenge_data: &[u8],
    nt_hash: &[u8],
    neg_flags: i64,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let lm_hash = e_des_hash_ntlmssp(password).0;

    let lm_response = smb_encrypt_hash_ntlmssp(&lm_hash, challenge_data);
    let nt_response = smb_encrypt_hash_ntlmssp(nt_hash, challenge_data);

    let session_key = if (neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) != 0 {
        smb_lm_session_keygen_ntlmssp(&lm_hash, &lm_response)
    } else {
        smb_session_keygen_ntv1_ntlmssp(nt_hash)
    };

    (lm_response, nt_response, session_key)
}

fn ntlmssp_genauth_ntlm2(
    challenge_data: &[u8],
    nt_hash: &[u8],
    rng: &mut impl Rng,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use digest::Digest;
    use hmac::{Hmac, Mac};
    use md5::Md5;

    let mut lm_response = (0..8).map(|_| rng.random::<u8>()).collect::<Vec<u8>>();
    lm_response.resize(16, 0);
    let lm_response = vec![0; 24];
    let mut session_nonce = challenge_data.to_vec();
    session_nonce.resize(8, 0);
    session_nonce.append(&mut lm_response[0..8].to_vec());

    let mut md5 = Md5::new();
    md5.update(challenge_data);
    md5.update(&lm_response[0..8]);
    let session_nonce_hash = md5.finalize().to_vec();

    let nt_response = smb_encrypt_hash_ntlmssp(nt_hash, &session_nonce_hash);
    let mut user_session_key = smb_session_keygen_ntv1_ntlmssp(nt_hash);

    user_session_key.resize(16, 0);
    let mut hmac = Hmac::<Md5>::new_from_slice(&user_session_key).unwrap();
    hmac.update(&session_nonce);
    let session_key = hmac.finalize().into_bytes().to_vec();

    (lm_response, nt_response, session_key)
}

fn ntlmssp_genauth_keyexchg(session_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let new_session_key: [u8; 16] = rand::rng().random();
    let encrypted_session_key = sam_oem_hash(&new_session_key, session_key);
    (encrypted_session_key, new_session_key.to_vec())
}

#[nasl_function(named(cryptkey, passhash))]
fn ntlmv1_hash(cryptkey: StringOrData, passhash: StringOrData) -> Vec<u8> {
    let cryptkey = cryptkey.data();
    let passhash = passhash.data();

    ep24(cryptkey, passhash)
}

fn ntlmv2_hash_gen(cryptkey: &[u8], passhash: &[u8], length: usize, rng: &mut impl Rng) -> Vec<u8> {
    let mut ntlmv2_client_data = (0..length).map(|_| rng.random::<u8>()).collect::<Vec<u8>>();

    let mut ntlmv2_response = smb_owf_encrypt_ntv2_ntlmssp(passhash, cryptkey, &ntlmv2_client_data);

    ntlmv2_response.append(&mut ntlmv2_client_data);

    ntlmv2_response
}

#[nasl_function(named(cryptkey, passhash, length))]
fn ntlmv2_hash(
    cryptkey: StringOrData,
    passhash: StringOrData,
    length: i64,
) -> Result<Vec<u8>, FnError> {
    let mut cryptkey = cryptkey.data().to_vec();
    cryptkey.resize(8, 0);
    let passhash = passhash.data();

    if passhash.len() != 16 {
        return Err(FnError::wrong_unnamed_argument(
            "passhash of length 16",
            &format!("passhash of length {}", passhash.len()),
        ));
    }

    if length < 0 {
        return Err(FnError::wrong_unnamed_argument(
            "length >= 0",
            &format!("length {}", length),
        ));
    }

    Ok(ntlmv2_hash_gen(
        &cryptkey,
        passhash,
        length as usize,
        &mut rand::rng(),
    ))
}

#[nasl_function(named(cryptkey, password, nt_hash, neg_flags))]
fn ntlm_response(
    cryptkey: StringOrData,
    password: StringOrData,
    nt_hash: StringOrData,
    neg_flags: i64,
) -> Result<Vec<u8>, FnError> {
    let cryptkey = cryptkey.data();
    let nt_hash = nt_hash.data();

    let (mut lm_response, mut nt_response, mut session_key) =
        ntlmssp_genauth_ntlm(&password.string(), cryptkey, nt_hash, neg_flags);

    lm_response.append(&mut nt_response);
    lm_response.append(&mut session_key);

    Ok(lm_response)
}

fn ntlm2_response_gen(
    cryptkey: &[u8],
    nt_hash: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>, FnError> {
    if nt_hash.len() < 16 {
        return Err(FnError::wrong_unnamed_argument(
            "nt_hash of length 16",
            &format!("nt_hash of length {}", nt_hash.len()),
        ));
    }

    let (mut lm_response, mut nt_response, mut session_key) =
        ntlmssp_genauth_ntlm2(cryptkey, nt_hash, rng);

    lm_response.append(&mut nt_response);
    lm_response.append(&mut session_key);

    Ok(lm_response)
}

#[nasl_function(named(cryptkey, password, nt_hash))]
fn ntlm2_response(
    cryptkey: StringOrData,
    #[allow(unused)] password: StringOrData,
    nt_hash: StringOrData,
) -> Result<Vec<u8>, FnError> {
    let mut cryptkey = cryptkey.data().to_vec();
    cryptkey.resize(8, 0);
    let nt_hash = nt_hash.data();
    ntlm2_response_gen(&cryptkey, nt_hash, &mut rand::rng())
}

#[nasl_function(named(cryptkey, user, domain, ntlmv2_hash, address_list, address_list_len))]
fn ntlmv2_response(
    cryptkey: StringOrData,
    #[allow(unused)] user: StringOrData,
    #[allow(unused)] domain: StringOrData,
    ntlmv2_hash: StringOrData,
    address_list: StringOrData,
    #[allow(unused)] address_list_len: usize,
) -> Result<Vec<u8>, FnError> {
    let cryptkey = cryptkey.data();
    let ntlmv2_hash = ntlmv2_hash.data();
    let address_list = address_list.data();

    let (mut lm_response, mut nt_response, mut user_session_key) =
        smb_ntlmv2_encrypt_hash_ntlmssp(ntlmv2_hash, cryptkey, address_list, &mut rand::rng());

    lm_response.append(&mut user_session_key);
    lm_response.append(&mut nt_response);

    Ok(lm_response)
}

#[nasl_function(named(cryptkey, session_key, nt_hash))]
fn key_exchange(
    #[allow(unused)] cryptkey: StringOrData,
    session_key: StringOrData,
    #[allow(unused)] nt_hash: StringOrData,
) -> Result<Vec<u8>, FnError> {
    let session_key = session_key.data();

    let (mut encrypted_session_key, mut new_session_key) = ntlmssp_genauth_keyexchg(session_key);
    new_session_key.append(&mut encrypted_session_key);

    Ok(new_session_key)
}

#[nasl_function]
fn lm_owf_gen(pass: StringOrData) -> Vec<u8> {
    let binding = pass.string().to_ascii_uppercase();
    let pass = binding.as_bytes();

    ep16(pass)
}

#[nasl_function]
fn nt_owf_gen(pass: StringOrData) -> Vec<u8> {
    use md4::{Digest, Md4};

    let pass_utf16: Vec<u8> = pass
        .string()
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hasher = Md4::new();
    hasher.update(&pass_utf16);
    hasher.finalize().to_vec()
}

#[nasl_function(named(owf, login, domain))]
fn ntv2_owf_gen(
    owf: StringOrData,
    login: StringOrData,
    domain: StringOrData,
) -> Result<Vec<u8>, FnError> {
    use hmac::{Hmac, Mac};
    use md5::Md5;

    let login = login.string();
    let domain = domain.string();
    let owf = owf.data();

    if login.is_empty() {
        return Err(FnError::wrong_unnamed_argument(
            "login of length >= 1",
            &format!("login of length {}", login.len()),
        ));
    }

    if domain.is_empty() {
        return Err(FnError::wrong_unnamed_argument(
            "domain of length >= 1",
            &format!("domain of length {}", domain.len()),
        ));
    }

    if owf.len() != 16 {
        return Err(FnError::wrong_unnamed_argument(
            "owf of length 16",
            &format!("owf of length {}", owf.len()),
        ));
    }

    let user: Vec<u8> = login
        .to_uppercase()
        .as_bytes()
        .iter()
        .flat_map(|b| [*b, 0u8])
        .collect();
    let domain: Vec<u8> = domain
        .to_uppercase()
        .as_bytes()
        .iter()
        .flat_map(|b| [*b, 0u8])
        .collect();

    // We can unwrap here, as the key is always 16 bytes.
    let mut hmac = Hmac::<Md5>::new_from_slice(owf).unwrap();
    hmac.update(&user);
    hmac.update(&domain);
    Ok(hmac.finalize().into_bytes().to_vec())
}

fn netbios_payload_len(buf: &[u8]) -> Option<usize> {
    // requires at least 4 bytes like the C code that indexes buf[1..3]
    if buf.len() < 4 {
        return None;
    }
    let b1 = buf[1] as usize;
    let b2 = buf[2] as usize;
    let b3 = buf[3] as usize;

    // Equivalent to:
    // (((unsigned)buf[3]) | (((unsigned)buf[2]) << 8) | ((((unsigned)buf[1]) & 1) << 16))
    let len = b3 | (b2 << 8) | ((b1 & 1) << 16);
    Some(len)
}

#[nasl_function(named(key, buf, buflen, seq_number))]
fn get_signature(
    key: &[u8],
    buf: &[u8],
    buflen: usize,
    seq_number: u32,
) -> Result<Vec<u8>, FnError> {
    use md5::Md5;

    let mut buf = buf.to_vec();
    if buf.len() < 26 {
        return Err(FnError::wrong_unnamed_argument(
            "buf of length >= 26",
            &format!("buf of length {}", buf.len()),
        ));
    }

    // Unwrap here is safe, as we have already checked the length of buf >= 26.
    let size = netbios_payload_len(&buf).unwrap();

    if buf.len() < size + 4 {
        return Err(FnError::wrong_unnamed_argument(
            &format!("buf of length >= {}", size + 4),
            &format!("buf of length {}", buf.len()),
        ));
    }

    let mut key = key.to_vec();
    key.resize(16, 0);

    let mut sequence_bytes = seq_number.to_le_bytes().to_vec();
    sequence_bytes.resize(8, 0);

    let ret = Md5::new()
        .chain_update(&key)
        .chain_update(&buf[4..18])
        .chain_update(&sequence_bytes)
        .chain_update(&buf[26..size + 4])
        .finalize()
        .to_vec();

    println!("MD5 Hash: {:02x?}", ret);

    buf[18..26].clone_from_slice(&ret[..8]);
    buf.resize(buflen, 0);
    Ok(buf)
}

pub struct Ntlm;

function_set! {
    Ntlm,
    (
        ntlm_response,
        ntlm2_response,
        ntlmv2_response,
        (ntlmv1_hash, "NTLMv1_HASH"),
        (ntlmv2_hash, "NTLMv2_HASH"),
        key_exchange,
        lm_owf_gen,
        nt_owf_gen,
        ntv2_owf_gen,
        get_signature,
    )
}
