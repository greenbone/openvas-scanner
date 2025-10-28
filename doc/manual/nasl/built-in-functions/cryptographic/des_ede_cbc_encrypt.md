# des_ede_cbc_encrypt

## NAME

**des_ede_cbc_encrypt** - encrypts given data with DES EDE CBC mode.

## SYNOPSIS

*str* **des_ede_cbc_encrypt**(key:str, data: str, iv: str);

**des_ede_cbc_encrypt** encrypts given data with triple DES EDE CBC mode.

## DESCRIPTION
Encrypt the given data using the triple DES EDE algorithm in CBC mode.

## RETURN VALUE

The return value is the encrypted data.

## ERRORS

Returns NULL when a given parameter is null.
