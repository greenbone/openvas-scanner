# rc4_encrypt

## NAME

**rc4_encrypt** - encrypts given data with rc4.

## SYNOPSIS

*str* **rc4_encrypt**(data: str, hd: int, iv: str, key: str);

**rc4_encrypt** encrypts given data with blowfish CBC mode.

## DESCRIPTION

Encrypt data with a RC4 cipher. 
If a perviously opened (RC4 handler)[open_rc4_cipher.md] exist the hd parameter should be set it will use the handler for encryption.

If there is no open handler than the key and iv parameter must be set.

  -data: string Data to decrypt
  -hd: the handler index. (mandatory if not key and iv is given)
  -iv: string Initialization vector (mandatory if no handler is given).
  -key: string key (mandatory if no handler is given).
## RETURN VALUE

The return value is the encrypted data.

## ERRORS

Returns NULL when there is no handler or no key and iv is provided.

## SEE ALSO

**[close_stream_cipher(3)](close_stream_cipher.md)**,
**[open_rc4_cipher(3)](open_rc4_cipher.md)**,
