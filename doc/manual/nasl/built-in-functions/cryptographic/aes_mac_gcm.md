# aes_mac_gcm

## NAME

**aes_mac_gcm** - takes two named arguments key, data

## SYNOPSIS

*str* **aes_mac_gcm**(key: str, data: str);

**aes_mac_gcm** It takes four named arguments key, data.

## DESCRIPTION

aes_mac_gcm encrypts given data with given key by using AES in GCM mode.
The according aes algorithm is dependent on the key size (if the key is 128 bit than AES128 is used, 256 and 512 are supported.)


## RETURN VALUE

Encrypted data

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[DES(3)](DES.md)**,
**[HMAC_MD2(3)](HMAC_MD2.md)**,
**[HMAC_MD5(3)](HMAC_MD5.md)**,
**[HMAC_RIPEMD160(3)](HMAC_RIPEMD160.md)**,
**[HMAC_SHA1(3)](HMAC_SHA1.md)**,
**[HMAC_SHA256(3)](HMAC_SHA256.md)**,
**[HMAC_SHA384(3)](HMAC_SHA384.md)**,
**[HMAC_SHA512(3)](HMAC_SHA512.md)**,
**[MD2(3)](MD2.md)**,
**[MD4(3)](MD4.md)**,
**[MD5(3)](MD5.md)**,
**[NTLMv1_HASH(3)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3)](NTLMv2_HASH.md)**,
**[RIPEMD160(3)](RIPEMD160.md)**,
**[SHA1(3)](SHA1.md)**,
**[SHA256(3)](SHA256.md)**,
**[SHA512(3)](SHA512.md)**,
**[aes128_cbc_encrypt(3)](aes128_cbc_encrypt.md)**,
**[aes128_ccm_decrypt(3)](aes128_ccm_decrypt.md)**,
**[aes128_ccm_decrypt_auth(3)](aes128_ccm_decrypt_auth.md)**,
**[aes128_ccm_encrypt(3)](aes128_ccm_encrypt.md)**,
**[aes128_ccm_encrypt_auth(3)](aes128_ccm_encrypt_auth.md)**,
**[aes128_ctr_encrypt(3)](aes128_ctr_encrypt.md)**,
**[aes128_gcm_decrypt(3)](aes128_gcm_decrypt.md)**,
**[aes128_gcm_decrypt_auth(3)](aes128_gcm_decrypt_auth.md)**,
**[aes128_gcm_encrypt(3)](aes128_gcm_encrypt.md)**,
**[aes128_gcm_encrypt_auth(3)](aes128_gcm_encrypt_auth.md)**,
**[aes256_cbc_encrypt(3)](aes256_cbc_encrypt.md)**,
**[aes256_ccm_decrypt(3)](aes256_ccm_decrypt.md)**,
**[aes256_ccm_decrypt_auth(3)](aes256_ccm_decrypt_auth.md)**,
**[aes256_ccm_encrypt(3)](aes256_ccm_encrypt.md)**,
**[aes256_ccm_encrypt_auth(3)](aes256_ccm_encrypt_auth.md)**,
**[aes256_ctr_encrypt(3)](aes256_ctr_encrypt.md)**,
**[aes256_gcm_decrypt(3)](aes256_gcm_decrypt.md)**,
**[aes256_gcm_decrypt_auth(3)](aes256_gcm_decrypt_auth.md)**,
**[aes256_gcm_encrypt(3)](aes256_gcm_encrypt.md)**,
**[aes256_gcm_encrypt_auth(3)](aes256_gcm_encrypt_auth.md)**,
**[aes_mac_cbc(3)](aes_mac_cbc.md)**,
**[aes_mac_gcm(3)](aes_mac_gcm.md)**,
**[bf_cbc_decrypt(3)](bf_cbc_decrypt.md)**,
**[bf_cbc_encrypt(3)](bf_cbc_encrypt.md)**,
**[bn_cmp(3)](bn_cmp.md)**,
**[bn_random(3)](bn_random.md)**,
**[close_stream_cipher(3)](close_stream_cipher.md)**,
**[des_ede_cbc_encrypt(3)](des_ede_cbc_encrypt.md)**,
**[dh_compute_key(3)](dh_compute_key.md)**,
**[dh_generate_key(3)](dh_generate_key.md)**,
**[dsa_do_sign(3)](dsa_do_sign.md)**
**[dsa_do_verify(3)](dsa_do_verify.md)**,
**[get_signature(3)](get_signature.md)**,
**[get_smb2_signature(3)](get_smb2_signature.md)**,
**[key_exchange(3)](key_exchange.md)**,
**[lm_owf_gen(3)](lm_owf_gen.md)**,
**[nt_owf_gen(3)](nt_owf_gen.md)**,
**[ntlm2_response(3)](ntlm2_response.md)**,
**[ntlm_response(3)](ntlm_response.md)**,
**[ntlmv2_response(3)](ntlmv2_response.md)**,
**[ntv2_owf_gen(3)](ntv2_owf_gen.md)**,
**[open_rc4_cipher(3)](open_rc4_cipher.md)**,
**[pem_to_dsa(3)](pem_to_dsa.md)**,
**[pem_to_rsa(3)](pem_to_rsa.md)**,
**[prf_sha256(3)](prf_sha256.md)**,
**[prf_sha384(3)](prf_sha384.md)**,
**[rc4_encrypt(3)](rc4_encrypt.md)**,
**[rsa_private_decrypt(3)](rsa_private_decrypt.md)**,
**[rsa_public_decrypt(3)](rsa_public_decrypt.md)**,
**[rsa_public_encrypt(3)](rsa_public_encrypt.md)**,
**[rsa_sign(3)](rsa_sign.md)**,
**[smb3kdf(3)](smb3kdf.md)**,
**[smb_cmac_aes_signature(3)](smb_cmac_aes_signature.md)**,
**[smb_gmac_aes_signature(3)](smb_gmac_aes_signature.md)**,
**[tls1_prf(3)](tls1_prf.md)**,
