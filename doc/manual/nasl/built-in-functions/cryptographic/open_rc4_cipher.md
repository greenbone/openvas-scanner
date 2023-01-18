# open_rc4_cipher

## NAME

**open_rc4_cipher** - opens an rc4 encryption handler for data stream encryptions.

## SYNOPSIS

_str_ **open_rc4_cipher**(key:str, iv: str);

**open_rc4_cipher** opens an rc4 encryption handler for data stream encryptions.

## DESCRIPTION

Open RC4 cipher to encrypt a stream of data. The handler can be used to encrypt stream data. 

Opened cipher must be closed with (close_stream_cipher)[close_stream_cipher.md] when it is not used anymore.

-iv: the initival vector
-key: the key used for encryption

## RETURN VALUE

Returns the id of the encrypted data cipher handler on success.

## ERRORS

Returns a negative number on failure.

## SEE ALSO

**[close_stream_cipher(3)](close_stream_cipher.md)**,
**[rc4_encrypt(3)](rc4_encrypt.md)**,
