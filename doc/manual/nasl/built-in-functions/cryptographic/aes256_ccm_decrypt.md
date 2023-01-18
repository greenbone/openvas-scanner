# aes256_ccm_decrypt

## NAME

**aes256_ccm_decrypt** - decrypts given encrypted data with AES 256 CCM mode.

## SYNOPSIS

*str* **aes256_ccm_decrypt**(key:str, iv: str, data: str, len: int);

**aes256_ccm_decrypt** decrypts given data with AES 256 CCM mode.

## DESCRIPTION
decrypt the given data using the AES 256 bit algorithm in CCM mode.

## RETURN VALUE

The return value is the decrypted data.
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
**[aes256_ccm_decrypt_auth(3)](aes256_ccm_decrypt_auth.md)**,
**[aes256_ccm_encrypt(3)](aes256_ccm_encrypt.md)**,
**[aes256_ccm_encrypt_auth(3)](aes256_ccm_encrypt_auth.md)**,
**[aes256_ctr_encrypt(3)](aes256_ctr_encrypt.md)**,
**[aes256_gcm_decrypt(3)](aes256_gcm_decrypt.md)**,
**[aes256_gcm_decrypt_auth(3)](aes256_gcm_decrypt_auth.md)**,
**[aes256_gcm_encrypt(3)](aes256_gcm_encrypt.md)**,
**[aes256_gcm_encrypt_auth(3)](aes256_gcm_encrypt_auth.md)**,
