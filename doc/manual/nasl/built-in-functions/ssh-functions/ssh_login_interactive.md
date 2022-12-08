# ssh_login_interactive

## NAME

**ssh_login_interactive** - starts an authentication process

## SYNOPSIS

*string* **ssh_login_interactive**(0: *int*, login: *string*);

**ssh_login_interactive** takes 1 positional and up to one named argument

## DESCRIPTION

The function starts an interactive user authentication process and pauses by the first non-echo prompt.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

The named argument *login* is a *string* and contains the user to login. It is only necessary if the login was not set before.

If a password is required for authentication, it has to be finished with **[ssh_login_interactive_pass(3)](ssh_login_interactive_pass.md)**.

Alternatively an non-interactive authentication can be done with **[ssh_userauth(3)](ssh_userauth.md)**.

## RETURN VALUE

A *string* containing the prompt or NULL on failure

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**, **[ssh_login_interactive_pass(3)](ssh_login_interactive_pass.md)**, **[ssh_userauth(3)](ssh_userauth.md)**