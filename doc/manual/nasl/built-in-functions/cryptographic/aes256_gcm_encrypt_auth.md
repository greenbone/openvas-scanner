# aes256_gcm_encrypt_auth

## NAME

**aes256_gcm_encrypt_auth** - encrypts given data including a authentication token with AES 256 GCM mode.

## SYNOPSIS

*str* **aes256_gcm_encrypt_auth**(key:str, iv: str, data: str, aad: str);

**aes256_gcm_encrypt_auth** encrypts given data including a authentication token with AES 256 GCM mode.

## DESCRIPTION
Encrypt the given data using the AES 256 bit algorithm in GCM mode including an authentication token given via aad.


## RETURN VALUE

The return value is the encrypted data.
## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

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
