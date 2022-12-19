# cert_query

## NAME

**cert_query** - query a certificate object

## SYNOPSIS

*any* **cert_query**(0: *int*, 1: *string*, idx: *int*);

**cert_query** takes 2 positional and up to 1 named arguments.

## DESCRIPTION

This function runs a command on a given certificate object.

The first unnamed argument is an *int* containing the certificate ID, given by **[cert_open(3)](cert_open.md)**.

The second unnamed argument is a *string* containing the command to run on the certificate object. Available commands are:
- *serial* - get the serial number of the certificate as a hex string
- *issuer* - get the issuer as *string* in the rfc-2253 format
- *subject* - get the subject of the certificate as *string* in the rfc-2253 format. To query the subjectAltName the named parameter *idx* with values starting at 1 can be used. In this case the format is either a *string* in rfc-2253 format, a rfc2822 mailbox name indicated by the first character being a left angle bracket or a S-expression in advanced format for all other types of subjectAltNames which is indicated by an opening parentheses.
- *not-before* - get the notBefore time as UTC value in ISO time format (e.g. "20120930T143521")
- *not-after* - get the notAfter time as UTC value in ISO time format (e.g. "20280929T143520")
- *all* - get all available information in a human readable format, **NOT YET IMPLEMENTED**
- *hostnames* - get an *array* containing all hostnames listed in the certificate, i.e. the CN part of the subject and all dns-name type subjectAltNames
- *fpr-sha-256* - get the SHA-256 fingerprint of the certificate. The fingerprint is, as usual, computed over the entire DER encode certificate
- *fpr-sha-1* get the SHA-1 fingerprint of the certificate. The fingerprint is, as usual, computed over the entire DER encode certificate.
- *image* - get the entire certificate as binary data
- *algorithm-name* - get the algorithm name used to sign the certificate. Get the OID of the digest algorithm and translate to a name from a list of Wireshark.
- *signature-algorithm-name* - same as *algorithm-name*
- *public-key-algorithm-name* - get the algorithm name of the public key
- *modulus* - get the RSA public key's modulus found in the structure of the given cert
- *exponent* - get the RSA public key's exponent found in the structure of the given cert
- *key-size* - get the size to hold the parameters size in bits, for RSA the bits returned is the modulus, for DSA the bits returned are of the public exponent

The named parameter *idx* is of type *int*. It used as an index for some of the commands. In general it gives the n-th value of a set of values. If not given 0 is used as default.

## RETURN VALUE

The return value depends of the type of command used. In general it can be a *string*, an *array* of strings or an *int*. In case of an error, the returned value is *NULL*.

## ERRORS

The given certificate is either missing or <0

The given certificate is not in use

No proper command passed

Unable to run given command

## SEE ALSO

**[cert_open(3)](cert_open.md)**
