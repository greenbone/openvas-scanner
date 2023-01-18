# aes256_ctr_encrypt

## NAME

**aes256_ctr_encrypt** - encrypts given data with AES 256 CTR mode.

## SYNOPSIS

*str* **aes256_ctr_encrypt**(key:str, iv: str, data: str);

**aes256_ctr_encrypt** encrypts given data with AES 256 CTR mode.

## DESCRIPTION
Encrypt the given data using the AES 256 bit algorithm in CTR mode.

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
**[aes256_gcm_decrypt(3)](aes256_gcm_decrypt.md)**,
**[aes256_gcm_decrypt_auth(3)](aes256_gcm_decrypt_auth.md)**,
**[aes256_gcm_encrypt(3)](aes256_gcm_encrypt.md)**,
**[aes256_gcm_encrypt_auth(3)](aes256_gcm_encrypt_auth.md)**,
