# ssh_userauth

## NAME

**ssh_userauth** - authenticate a user on a SSH connection

## SYNOPSIS

*int* **ssh_userauth**(0: *int*, login: *string*, password: *string*, privatekey: *string* passphrase: *string*);

**ssh_userauth** takes 1 positional and up to 3 named arguments.

## DESCRIPTION

This function authenticates a user for a SSH connection to be able to use it.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

The named argument *login* is a *string* and contains the user to login. It is only necessary if the login was not set before. If missing and not set before the kb entry set in *Secret/SSH/login* is used. Given that many servers don't allow changing the login for an established connection, the *login* parameter is silently ignored on all further calls. Can also be set with **[ssh_set_login(3)](ssh_set_login.md)**.

The named parameter *password* contains the password for the user given in *login* as *string*. If set, the function performs a password based authentication, else a public key authentication is performed instead.

To perform a public key based authentication, the named argument *privatekey* is used. It contains a base64 private key in either SSH native or in PKCS#8 format as *string*.

The named argument *passphrase* contains a passphrase as a *string*. It is used for public key based authentication with a protected key.

If both *password* and *privatekey* are given, only *password* is used. If neither are given the value ar taken from the KB:
- *Secret/SSH/password* for *password*
- *Secret/SSH/privatekey* for *privatekey*
- *Secret/SSH/passphrase* for *passphrase*

Note that the named argument *publickey* and the KB item *Secret/SSH/publickey* are ignored. They are not longer required, because they can be derived from the private key.

Alternatively an interactive authentication can be done with **[ssh_login_interactive(3)](ssh_login_interactive.md)** and **[ssh_login_interactive_pass(3)](ssh_login_interactive_pass.md)**.

## RETURN VALUE

An *int* as status value, where 0 indicates a success.

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**, **[ssh_set_login(3)](ssh_set_login.md)**, **[ssh_login_interactive(3)](ssh_login_interactive.md)**, **[ssh_login_interactive_pass(3)](ssh_login_interactive_pass.md)**