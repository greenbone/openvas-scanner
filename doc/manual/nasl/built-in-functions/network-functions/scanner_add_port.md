# scanner_add_port

## NAME

**scanner_add_port** - declares an open port to openvas-scanner.

## SYNOPSIS

*void* **scanner_add_port**(port: *int, proto: *string*);

**scanner_add_port** takes two named arguments:
- port: is the port number.
- proto: is "tcp" or "udp". This is optional and "tcp" is the default.

## DESCRIPTION

Declares an open port to openvas-scanner.

## RETURN VALUE

Return FAKE_CELL

## ERRORS

- Invalid socket value
