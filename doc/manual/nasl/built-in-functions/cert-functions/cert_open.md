# cert_open

## NAME

**cert_open** - create a certificate object

## SYNOPSIS

*int* **cert_open**(0: *string*);

**cert_open** takes one positional argument.

## DESCRIPTION

Takes a string/data as unnamed argument and returns an identifier used with the other cert functions. The data is usually the BER encoded certificate but the function will also try a PEM encoding on failure to parse BER encoded one. An opened certificate object must be closed with **[cert_close(3)](cert_close.md)**.

The first unnamed argument is either *string* or a data object containing the certificate. It is either Binary or PEM encoded.

## RETURN VALUE

Identifier for the certificate object as *int* or *NULL* on error.

## ERRORS

First unnamed argument is missing.

Unable to create certificate object.

## SEE ALSO

**[cert_close(3)](cert_close.md)**
