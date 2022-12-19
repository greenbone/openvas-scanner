# cert_close

## NAME

**cert_close** - release a certificate object

## SYNOPSIS

*void* **cert_close**(0: *int*);

**cert_close** takes one unnamed argument.

## DESCRIPTION

This function releases a certificate object, which was created by **[cert_open(3)](cert_open.md)** before.

The first unnamed argument is an *int* and contains an identifier to a cert object. This identifier is returned by **[cert_open(3)](cert_open.md)**.

## RETURN VALUE

None

## ERRORS

The first unnamed argument is missing

The given object ID is <0

The given object ID is not in use

## SEE ALSO

**[cert_open(3)](cert_open.md)**
