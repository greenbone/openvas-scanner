# wmi_connect_rsop

## NAME

**wmi_connect_rsop** - Connect to a WMI service on the current target system to the RSoP namespace

## SYNOPSIS

*int* **wmi_connect**(username: *string*, password: *string*, ns: *string*, option: *string*);
*int* **wmi_connect_rsop**(username: *string*, password: *string*, option: *string*);
*int* **wmi_connect_reg**(username: *string*, password: *string*, option: *string*);

## DESCRIPTION

**wmi_connect** connects to a WMI service on the current target system into a specified namespace.

**wmi_connect_rsop** connects to a WMI service on the current target system into the RSoP namespace.

**wmi_connect_reg** connects to a WMI service on the current target system into the registry namespace.

A WMI handler is returned, which is used to run commands on the target system. A opened handler must be closed by calling **[wmi_close(3)](wmi_close.md)**.

The named argument *username* contains the user login.

The named argument *password* contains the password.

The optional named argument *ns* contains the namespace to use. The default namespace is *root\\cimv2*.

The optional named argument *option* is a *string* containing options for the WMI connection. The option must be given in the format "\[opt1, opt2, ...\]". here a list of all options:
- sign: Use RPC integrity authentication level
- seal: Enable RPC privacy (encryption) authentication level
- connect: Use RPC connect level authentication (auth, but no sign or seal)
- spnego: Use SPNEGO instead of NTLMSSP authentication
- ntlm: Use plain NTLM instead of SPNEGO or NTLMSSP
- krb5: Use Kerberos instead of NTLMSSP authentication
- validate: Enable the NDR validator
- print: Enable debug output of packets
- padcheck: Check reply data for non-zero pad bytes
- bigendian: Use big endian for RPC
- smb2: Use SMB2/3 for named pipes

## RETURN VALUE

An *int* representing the WMI handle or *NULL* on error.

## ERRORS

One of the named arguments *username* or *password* are missing or empty.

Unable to get IP of target system.

WMI connection failed or missing WMI support.

## EXAMPLE
1. Integrated example of an :
```c#
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );

if(!usrname || !passwd) exit( 0 );

domain = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

opts = "[sign]";
handle = wmi_connect(username:usrname, password:passwd, options:opts);

if( ! handle ) exit( 0 );

a = wmi_query( wmi_handle:handle, query:"select * from Win32_ComputerSystem");
display (a);

wmi_close( wmi_handle:handle );

set_kb_item( name:"WMI/access_successful", value:TRUE );
set_kb_item( name:"SMB_or_WMI/access_successful", value:TRUE );
```

## NOTE

In order to be able to use the WMI client of the openvas-scanner, **[openvas-smb](https://github.com/greenbone/openvas-smb)** has to be installed.

## SEE ALSO

**[wmi_close(3)](wmi_close.md)**
