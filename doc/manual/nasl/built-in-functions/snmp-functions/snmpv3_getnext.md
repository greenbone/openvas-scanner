# snmpv3_getnext

## NAME

**snmpv3_getnext** - get the next snmp v3 value query based on the last value

## SYNOPSIS

*array* **snmpv1_get**(port: *int*, protocol: *string*, community: *string*, oid: *string*);
*array* **snmpv1_getnext**(port: *int*, protocol: *string*, community: *string*, oid: *string*);
*array* **snmpv2c_get**(port: *int*, protocol: *string*, community: *string*, oid: *string*);
*array* **snmpv2c_getnext**(port: *int*, protocol: *string*, community: *string*, oid: *string*);
*array* **snmpv3_get**(port: *int*, protocol: *string*, community: *string*, oid: *string*);
*array* **snmpv3_getnext**(port: *int*, protocol: *string*, username: *string*, authpass: *string*, authproto: *string*, privpass: *string*, privproto: string);


## DESCRIPTION

All function in this family are similar. They all get return information about a SNMP network device. SNMP stands for Simple Network Management Protocol. The function in this family allow to get available devices and iterate though them.

The named argument *port* is an *int* containing the port number.

The named argument *protocol* is and *string* used for the protocol used.

The named argument *community* contains the community string.

The named argument *oid* contains the OID of ans SNMP device. For **snmpv1_get** and **snmpv2c_get** this argument is always necessary, as this functions will return information about a specific device. **snmpv1_getnext** and **snmpv2c_getnext** on the other hand need this argument only on the first call to get an entry point from which the iteration through the devices can start. In fact on successive calls, this argument is ignored internally.

The named argument *username* contains the name of the user for SNMPv3 authentication as *string*.

The named argument *authpass* contains the password for the user authentication as *string*.

The named argument *authproto* contains the hash algorithm used for encrypting the authentication. Either *md5* or *sha1* must be used.

The named argument *privpass* contains a password used for encrypting the data sent as *string*.

The named argument *privproto* contains the hash algorithm used for encrypting the sent data. Either *des* or *aes* must be used.

## RETURN

For **snmpv1_get**, **snmpv2c_get** and **snmpv3_get** an *array* of size 2 containing a return code as *int* in the first position and the name of the device as *string* on the second.

For **snmpv1_getnext**, **snmpv2c_getnext** and **snmpv3_getnext** an *array* of size 3 containing a return code as *int* in the first position. The name of the device as *string* on the second and the OID of the next device as *string* on the third position.


## ERROR

In case of an Error these functions return an *array* containing two values. The first is always an error code as *int* and the second one a reason as *string*

Error can be caused by:
- An missing function argument
- Invalid port value
- Invalid protocol value

## EXAMPLE

1. Display SNMP v1 network device and iterate through the next 5 entries:
```c++
oid = '.1.3.6.1.2.1.1.1.0';

protocol = 'udp';
port = 161;
community = 'public';

display("version 1");
ret = snmpv1_get( port:port, oid:oid, protocol:protocol, community:community );
display (ret);
 
display("\n\n\n\ngetnext version 1 ");
for (i = 0; i < 5; i++)
{   
    ret = snmpv1_getnext( port:port, protocol:protocol, community:community );
    display (ret);
}     

```

2. Display SNMP v2 network device and iterate through the next 5 entries:
```c++
oid = '.1.3.6.1.2.1.1.1.0';

protocol = 'udp';
port = 161;
community = 'public';

display("version 2c");
ret = snmpv2c_get( port:port, oid:oid, protocol:protocol, community:community );
display (ret, "\n");
display("getnext version 2c . No OID (optional), because it was alredy stored during the last call with an oid\n");
for (i = 0; i < 5; i++)
{   
    ret = snmpv2c_getnext( port:port, protocol:protocol, community:community );
    display (ret);
}   
```

3. Display SNMP v3 network device and iterate though the next 6 entries:
```c++
oid = '.1.3.6.1.2.1.1.1.0';

port = 161;
user = "user";
pass = "password";
passph = "password";
 
display("\n\n\n");
display("version 3\n");
 
ret = snmpv3_get(port:port, protocol:"udp", username:user, oid:oid,
                  authpass:pass, authproto:"sha1", privpass:passph,
                  privproto:"aes");
display (ret, "\n");
 
display("getnext WITH oid (optinal)");
ret = snmpv3_getnext(port:port, protocol:"udp", username:user, oid:oid,
                  authpass:pass, authproto:"sha1", privpass:passph,
                  privproto:"aes");
display (ret, "\n");
 
display("getnext WITHOUT oid (which is optional. Using the last one from teh last call)");
for (i = 0; i< 5; i++)
{
        ret = snmpv3_getnext(port:port, protocol:"udp", username:user,
                  authpass:pass, authproto:"sha1", privpass:passph,
                  privproto:"aes");
        display (ret);
 }
```

## SEE ALSO

**[snmpv1_get(3)](snmpv1_get.md)**, **[snmpv1_getnext(3)](snmpv1_getnext.md)**, **[snmpv2c_get(3)](snmpv2c_get.md)**, **[snmpv2c_getnext(3)](snmpv2c_getnext.md)**, **[snmpv3_get(3)](snmpv3_get.md)** 