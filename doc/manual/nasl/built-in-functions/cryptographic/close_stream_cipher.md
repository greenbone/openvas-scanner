# close_stream_cipher

## NAME

**close_stream_cipher** - closes a stream cipher.

## SYNOPSIS

*str* **close_stream_cipher**(hd: int);

**close_stream_cipher** closes a stream cipher.

## DESCRIPTION
Closes a stream cipher.

## RETURN VALUE
0 when the hd is closed.

## ERRORS

Returns NULL when the handler given by the hd index was not found.

## SEE ALSO

**[rc4_encrypt(3)](rc4_encrypt.md)**,
