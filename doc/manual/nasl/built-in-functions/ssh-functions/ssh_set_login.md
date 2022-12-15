# ssh_set_login

## NAME

**ssh_set_login** - set the login name for authentication

## SYNOPSIS

*NULL* **ssh_set_login**(0: *int*, login: *string*);

**ssh_set_login** takes 1 positional and 1 named argument

## DESCRIPTION

This function is optional and usually not required. However, if you want to get the banner, like in **[ssh_get_issue_banner](ssh_get_issue_banner.md)**, before starting the authentication you need to tell libssh the user because it is often not possible to change the user after the first call to an authentication method - getting the banner uses an authentication function.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

The optional named argument *login* is an *string* parameter. It is used for the login name. It should contain the user name to login.

If the *login* parameter is not given the default set in the kb in *Secret/SSH/login* is used instead.

Given that many servers don't allow changing them for an established connection, the *login* parameter is silently ignored on all further authentication calls that requires it.

## RETURN VALUE

*NULL*

## ERRORS

Failed to get SSH username

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**, **[ssh_get_issue_banner](ssh_get_issue_banner.md)**