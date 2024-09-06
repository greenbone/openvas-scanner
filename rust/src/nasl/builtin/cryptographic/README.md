# nasl-builtin-cryptographic

Implements cryptographic functions within NASL.

It is part of the std lib which is proven by the tests.

To use this module you have to initiate Cryptographic and look for the function:

```
let functions = nasl_builtin_utils::NaslfunctionRegisterBuilder::new()
    .push_register(nasl_builtin_cryptographic::Cryptographic)
    .build();
```

## Implemented

- aes_mac_cbc
- aes_cmac
- aes128_gcm_encrypt
- aes128_gcm_encrypt_auth
- aes128_gcm_decrypt
- aes128_gcm_decrypt_auth
- aes192_gcm_encrypt
- aes192_gcm_encrypt_auth
- aes192_gcm_decrypt
- aes192_gcm_decrypt_auth
- aes256_gcm_encrypt
- aes256_gcm_encrypt_auth
- aes256_gcm_decrypt
- aes256_gcm_decrypt_auth
- aes128_ctr_encrypt
- aes128_ctr_decrypt
- aes192_ctr_encrypt
- aes192_ctr_decrypt
- aes256_ctr_encrypt
- aes256_ctr_decrypt
- aes128_cbc_encrypt
- aes128_cbc_decrypt
- aes192_cbc_encrypt
- aes192_cbc_decrypt
- aes256_cbc_encrypt
- aes256_cbc_decrypt
- aes128_ccm_decrypt
- aes128_ccm_decrypt_auth
- aes128_ccm_encrypt
- aes128_ccm_encrypt_auth
- aes256_ccm_decrypt
- aes256_ccm_decrypt_auth
- aes256_ccm_encrypt
- aes256_ccm_encrypt_auth
- aes_mac_gcm
- HMAC_MD2
- HMAC_MD5
- HMAC_RIPEMD160
- HMAC_SHA1
- HMAC_SHA256
- HMAC_SHA384
- HMAC_SHA512
- MD2
- MD4
- MD5
- RIPEMD160
- SHA1
- SHA256
- SHA512

## Not yet implemented

- DES
- NTLMv1_HASH
- NTLMv2_HASH
- bf_cbc_decrypt
- bf_cbc_encrypt
- bn_cmp
- bn_random
- close_stream_cipher
- des_ede_cbc_encrypt
- dh_compute_key
- dh_generate_key
- dsa_do_sign
- dsa_do_verify
- get_signature
- get_smb2_signature
- index
- insert_hexzeros
- key_exchange
- lm_owf_gen
- nt_owf_gen
- ntlm2_response
- ntlm_response
- ntlmv2_response
- ntv2_owf_gen
- open_rc4_cipher
- pem_to_dsa
- pem_to_rsa
- prf_sha256
- prf_sha384
- rc4_encrypt
- rsa_private_decrypt
- rsa_public_decrypt
- rsa_public_encrypt
- rsa_sign
- smb3kdf
- smb_cmac_aes_signature
- smb_gmac_aes_signature
- tls1_prf

