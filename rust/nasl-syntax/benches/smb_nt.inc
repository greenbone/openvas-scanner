# This file is neither compiled into a distribution nor is it part of the distribution.
# The sole purpose is to test the scanner during build time.
# SPDX-FileCopyrightText: 2004 Anonymous
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Global TODO: - Dedupliacte code tagged with <- START TODO: This duplicated code just makes this include huge and un-maintainable
#              - Check the # TBD: marked items

global_var multiplex_id, g_mhi, g_mlo, s_sign_key, initial, seq_number, ct_flag, ntlmssp_flag, ntlmv2_flag, isSignActive, smb;
global_var sign_key, encryptKey, decryptKey;
global_var smbv3, smbv2, smbEncryption;
global_var server_guid, serv_sec_mode, serv_capabilities, serv_dialect, client_guid;

# Global keys to avoid that we're repeatedly asking redis for something we already know
global_var __kb_smb_name, __kb_smb_domain, __kb_smb_login, __kb_smb_password, __kb_smb_transport, __kb_smb_is_samba;

ntlmv2_flag  = string( get_kb_item( "SMB/dont_send_ntlmv1" ) );
ct_flag      = string( get_kb_item( "SMB/dont_send_in_cleartext" ) );

## An ISSUE reported as #71142, registry methods of smb_nt.inc are currently failing
## against a Windows Vista Ulimate SP1 and Windows Server (R) 2008 SP1 systems. Moreover,
## Windows Vista has already reached End of Life.
## Adding a workaround to check if target is Windows Vista Service Pack 1 or Windows Server
## (R) 2008 Service Pack 1 and if so force target to use SMB1 instead of SMB2, which is
## working fine.

_Workaround = get_kb_list( "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.102011/OS" );

if( _Workaround ) {
  foreach __Workaround( _Workaround ) {
    if( ( "Windows Vista (TM) Ultimate 6001 Service Pack 1" >< __Workaround )||
        ( "windows_vista" >< __Workaround && "sp1" >< __Workaround )||
        ( "Windows Server (R) 2008 Enterprise 6001 Service Pack 1" >< __Workaround )||
        ( "windows_server_2008" >< __Workaround && "sp1" >< __Workaround && "r2" >!< __Workaround ) ) {
      ntlmssp_flag = 0;
      break;
    }
  }
}

if( ntlmssp_flag ) {
  multiplex_id = 1;
} else {
  multiplex_id = rand();
}

isSignActive = 0;

g_mhi = multiplex_id / 256;
g_mlo = multiplex_id % 256;

# @brief Returns the known NetBIOS name of the target host saved within the knowledge base. To avoid
#        querying the KB for the same info again it will be cached within an internal variable.
#
# @return The known NetBIOS name of the target host and (if none is known) the IP of the target.
#
function kb_smb_name() {

  local_var name;

  if( ! isnull( __kb_smb_name ) ) {
    name = string( __kb_smb_name );
  } else {
    name = string( get_kb_item( "SMB/name" ) );
    if( strlen( name ) > 0 ) {
      __kb_smb_name = name;
    } else {
      name = get_host_ip();
      __kb_smb_name = name;
    }
  }
  return name;
}

# @brief Returns the known NetBIOS domain of the target host from the knowledge base.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
# @note The return value could be NULL if no entry is found. I miss the knowledge for that.
# @return Always returns the known NetBIOS name of the target host.
function kb_smb_domain() {

  local_var domain;

  if( ! isnull( __kb_smb_domain ) ) {
    domain = string( __kb_smb_domain );
  } else {
    domain = string( get_kb_item( "SMB/domain" ) );
    __kb_smb_domain = domain;
  }
  return domain;
}

# @brief Returns the known username.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
# @note The return value could be NULL if no entry is found. I miss the knowledge for that.
# @return Always returns the known username for the current client.
function kb_smb_login() {

  local_var login;

  if( ! isnull( __kb_smb_login ) ) {
    login = string( __kb_smb_login );
  } else {
    login = string( get_kb_item( "SMB/login" ) );
    __kb_smb_login = login;
  }
  return login;
}

# @brief Returns the known password.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
# @note The return value could be NULL if no entry is found. I miss the knowledge for that.
# @return Always returns the known password for the current client.
function kb_smb_password() {

  local_var password;

  if( ! isnull( __kb_smb_password ) ) {
    password = string( __kb_smb_password );
  } else {
    password = string( get_kb_item( "SMB/password" ) );
    __kb_smb_password = password;
  }
  return password;
}

# @brief Returns the known port for the connection.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
# @note The return value could be NULL if no entry is found. I miss the knowledge for that.
# @return Returns the know port for the connection. If no port is currently set in the KB
#         it will check if port 445 is free. If this is not the case the functions exits with code zero.
function kb_smb_transport() {

  local_var transport;

  if( ! isnull( __kb_smb_transport ) ) {
    transport = __kb_smb_transport;
  } else {
    transport = get_kb_item( "SMB/transport" );
    if( transport ) {
      transport = int( transport );
      __kb_smb_transport = transport;
    } else {
      transport = 445;
      if( ! get_port_state( transport ) ) exit( 0 );
      __kb_smb_transport = transport;
    }
  }
  return transport;
}

# @brief Returns an array containing all required info to do a connection to a WMI or SMB endpoint.
#
# @return An array containing all required connection info with the following keys and values:
#
#         array["domain"]           -> The user specified domain.
#         array["host"]             -> The IP of the target host.
#         array["netbios_name"]     -> The NetBIOS name of the target.
#         array["password"]         -> The user specified password.
#         array["transport_port"]   -> The identified port/transport for a SMB connection.
#         array["username_plain"]   -> The plain user specified username.
#         array["username_wmi_smb"] -> The user specified username and in case a domain was specified also contains the domain in a form of domain\username.
#         array["username_wincmd"]  -> The user specified username and in case a domain was specified also contains the domain in a form of domain/username.
#
#         FALSE in the case if any of the required data (host, username or password) is missing in the knowledge base.
#
function kb_smb_wmi_connectinfo() {

  local_var host, usrname, passwd, usrname_wmi_smb, usrname_wincmd, domain, netbios_name, transport_port, ret;

  host    = get_host_ip();
  usrname = kb_smb_login();
  passwd  = kb_smb_password();

  if( ! host || ! usrname || ! passwd )
    return FALSE;

  usrname_wmi_smb = usrname;
  usrname_wincmd  = usrname;

  domain = kb_smb_domain();
  if( domain ) {
    usrname_wmi_smb = domain + '\\' + usrname;
    usrname_wincmd  = domain + '/' + usrname;
  }

  netbios_name   = kb_smb_name();
  transport_port = kb_smb_transport();

  ret = make_array();
  ret["domain"]           = domain;
  ret["host"]             = host;
  ret["netbios_name"]     = netbios_name;
  ret["password"]         = passwd;
  ret["transport_port"]   = transport_port;
  ret["username_plain"]   = usrname;
  ret["username_wmi_smb"] = usrname_wmi_smb;
  ret["username_wincmd"]  = usrname_wincmd;
  return ret;
}

# @brief Returns the info if the remote host is a Samba server.
#
# @note VTs calling this function needs a dependency to netbios_name_get.nasl
#       and smb_nativelanman.nasl.
#
# @return TRUE if the remote host is a Samba server, FALSE otherwise
#
function kb_smb_is_samba() {

  local_var is_samba, lanman;

  if( ! isnull( __kb_smb_is_samba ) ) {
    is_samba = __kb_smb_is_samba;
  } else {
    lanman = get_kb_item( "SMB/NativeLanManager" );
    if( strlen( lanman ) > 0 ) {
      if( "samba" >< tolower( lanman ) ) {
        is_samba = TRUE;
      } else {
        is_samba = FALSE;
      }
    } else {
      if( get_kb_item( "SMB/samba" ) ) {
        is_samba = TRUE;
      } else {
        is_samba = FALSE;
      }
    }
    __kb_smb_is_samba = is_samba;
  }
  return is_samba;
}

# @brief Provides a mapping between a Windows 10 or Windows 11 build number and version.
#
# @param string - a string containing the build number like: Windows 10 Pro 10586
# @param win_name - an exact name of the Windows release, currently only accepting: win10, win11
#
# @return Returns the Windows 10 or Windows 11 version for a build number or NULL otherwise (
#         if no matching build / version was found).
#
function get_version_from_build( string, win_name ) {

  local_var string, win_name;

  if( ! string ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#string#-#get_version_from_build" );
    return;
  }

  if( ! win_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#win_name#-#get_version_from_build" );
    return;
  }

  if( win_name == "win10" ) {
    # https://en.wikipedia.org/wiki/Windows_10_version_history for the version <> build mapping
    if( "10240" >< string ) return "1507";
    if( "10586" >< string ) return "1511";
    if( "14393" >< string ) return "1607";
    if( "15063" >< string ) return "1703";
    if( "16299" >< string ) return "1709";
    if( "17134" >< string ) return "1803";
    if( "17763" >< string ) return "1809";
    if( "18362" >< string ) return "1903";
    if( "18363" >< string ) return "1909";
    if( "19041" >< string ) return "2004";
    if( "19042" >< string ) return "20H2";
    if( "19043" >< string ) return "21H1";
    if( "19044" >< string ) return "21H2";
    if( "19045" >< string ) return "22H2";
  }
  else if( win_name == "win11" ) {
    if( "22000" >< string ) return "21H2";
    if( "22621" >< string ) return "22H2";
  }
  return;
}

# @brief Accepts hexadecimal string and converts it into decimal

# @param str The hexadecimal string that needs to be converted
# @return Returns a decimal value
function hextodec( str ) {

  local_var str, str_up, digits, len, i, j, flag;

  if( isnull( str ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#str#-#hextodec" );

  str_up = toupper( str );
  digits = "0123456789ABCDEF";
  len = strlen( str_up ) - 1;
  for( i = 0; i <= len; i++ ) {
    for( j = 0; j < strlen( digits ); j++ ) {
      if( str_up[i] == digits[j] ) {
        flag += j*(16**(len - i));
      }
    }
  }
  return flag;
}

# Reads a SMB packet
# @brief Accepts a socket and reads a packet from it.

# @param socket The socket that is used for the connection
# @return Returns the data that was read or in case it fails NULL.
function smb_recv( socket ) {

  local_var socket, header, len, trailer, nonce, aad, crypt, signature, encrypted, data;

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smb_recv" );
    return NULL;
  }

  # Receive the data from the given socket.
  # We want to read maximum 4 bytes into the local_var header
  # The first 4 bytes represent the Netbios Session Service with its context and length
  header = recv( socket:socket, length:4, min:4 );
  if( strlen( header ) < 4 ) return NULL;

  # Calculate the expected length based on the values from the NetBIOS Session Service Length field
  len = 256 * ord( header[2] );
  len += ord( header[3] );
  if( len == 0 ) return header;

  # Read maximum number of bytes that are calculated before
  trailer = recv( socket:socket, length:len, min:len );
  if( strlen( trailer ) < len ) return NULL;

  # Verify that the transform header signature is correct
  # Decrpyt the encryption data and craft a packet with the correct length but without the transform header
  # We delete the transform header after this step because else we would need to restructure every other function
  # These checks are in accordance with [MS-SMB2 3.3.5.2.1.1]
  # We should only decrypt the received packages that are encrypted of course
  if( smbEncryption && ord( trailer[0] ) == 253 ) {
    # Transform Header is too short
    if( strlen( trailer ) < 52 ) return NULL;
    # Flag is not correct set
    if( hexstr( substr( trailer, 41, 42 ) ) != "0001" ) return NULL;

    # 11 Byte nonce for AES-128-CCM
    nonce = substr( trailer, 20, 30 );
    aad = nonce + substr( trailer, 31, 51 );

    data = substr( trailer, 52, len-1 );

    crypt = aes128_ccm_decrypt_auth( key:decryptKey, iv:nonce, data:data, len:strlen( data ), aad:aad );

    decrypt = crypt[0];
    tag = crypt[1];

    # Check if the calculated tag matches with the received signature of the transform header
    if( tag != substr( trailer, 4, 19 ) ) return NULL;

    # Craft the NetBIOS Session Servicce
    header = substr( header, 0 , 0 );
    len = strlen( decrypt );
    header += raw_string( 0x00, len/256, len%256 );

    # Make the decrpyted part the trailer of the packet.
    trailer = decrypt;

  }

  if( header && trailer ) {
    return strcat( header, trailer );
  }
}

# @brief Accepts a netbios name and a netbios service and encodes them.
# @note Encode name and service to the netbios network format
# @param data The data that needs to be encoded into the netbios format
# @param service Number of bytes in the label
# @return Returns the encoded nebtios data
function netbios_encode( data, service ) {

  local_var data, service, tmpdata, ret, i, o, odiv, omod, c;

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#netbios_encode" );
    return NULL;
  }

  if( isnull( service ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#service#-#netbios_encode" );

  ret = "";
  tmpdata = data;

  while( strlen( tmpdata ) < 15 ) {
    tmpdata += " ";
  }

  # Encoding in accordance with RFC 1001 section 14.1
  # https://www.rfc-editor.org/rfc/rfc1001.html

  tmpdata += raw_string( service );
  for( i = 0; i < 16; i++ ) {
    o = ord( tmpdata[i] );
    odiv = o/16;
    odiv = odiv + ord("A");
    omod = o%16;
    omod = omod + ord("A");
    c = raw_string( odiv, omod );
    ret += c;
  }
  return ret;
}

# @brief Accepts a netbios name and encodes it.
# @note Calls netbios_encode.
# @param orig The name that needs to be encoded into the netbios format
# @return Returns the encoded nebtios data
function netbios_name( orig ) {

  local_var orig;

  if( isnull( orig ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#orig#-#netbios_name" );

  return netbios_encode( data:orig, service:0x20 );
}

# @brief Returns the netbios name of a redirector
# @return Returns the netbios name of a redirector that seems to be always not existent.
function netbios_redirector_name() {

  local_var ret;

  # 30 encoded Spaces
  ret = crap( data:"CA", length:30 );
  ret += "AA";
  return ret;
}

# @brief Accepts data and interprets it as unicode.
# @note return a 28 + strlen(data) + (odd(data)?0:1) long string
# @param data The data that is interpreted as unicode
# @return Returns the interpreted unicode string.
function unicode( data ) {

  local_var data, len, ret, i, even;

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#unicode" );
    return NULL;
  }

  len = strlen( data );

  # Get integer of ASCII and encode it into a character in a string
  if( len > 0 ) {
    ret = raw_string( ord( data[0] ) );
  }

  for( i = 1; i < len; i++ ) {
    ret = string( ret, raw_string( 0, ord( data[i] ) ) );
  }

  if( ! ( len & 1 ) ) {
    even = 1;
  } else {
    even = 0;
  }

  for( i = 0; i < 7; i++ ) {
    ret += raw_string( 0 );
  }

  if( even ) {
    ret += raw_string( 0x00, 0x00 );
  }
  return ret;
}


# @brief Accepts a socket and a remote hostname and makes the netbios session request but only when port 445 is not used.
# @note Port 445 is nearly always used. Currently in the Community Feed one package that uses port 139 with this request has been noticed.
# @param soc The socket used for the connection
# @param remote The remote hostname.
# @return Returns the answer to the netbios request or TRUE if port 445 is used. In case of an failure FALSE is returned.
function smb_session_request( soc, remote ) {

  local_var soc, remote, trp, nb_remote, nb_local, session_request, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_session_request" );
  if( isnull( remote ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#remote#-#smb_session_request" );

  trp = kb_smb_transport();
  # We don't need to request a session when talking on top of port 445
  # This is because then we use the TCP Stack directly and do not need the older NETBIOS implementation
  if( trp == 445 ) {
    return TRUE;
  }

  # netbios_name is a function that converts a netbios name to the netbios network format
  # it calls the subfunction netbios_encode

  nb_remote = netbios_name( orig:remote );
  nb_local  = netbios_redirector_name();

  # 0x81 describes the NETBIOS message type
  # 0x00 00 44 are some flags and the length
  # The 0x20 is relevant for the netbios encode in RFC 1001

  session_request = raw_string( 0x81, 0x00, 0x00, 0x44 ) +
                    raw_string( 0x20 ) +
                    nb_remote +
                    raw_string( 0x00, 0x20 ) +
                    nb_local +
                    raw_string( 0x00 );
  send( socket:soc, data:session_request );
  r = smb_recv( socket:soc );
  if( isnull( r ) ) return FALSE;

  if( ord( r[0] ) == 0x82 ) {
    return r;
  } else {
    return FALSE;
  }
}


# @brief Accepts a SMB reply and extracts the session id.
# @note Extract the UID from the result of smb_session_setup() <-- Previous comment
# @param reply The SMB reply that is used.
# @return Returns the id of the session
function session_extract_uid( reply ) {

  local_var reply, uid, low, high;

  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#session_extract_uid" );

  if( strlen( reply ) < 5 ) return FALSE;

  if( ord( reply[4] ) == 254 ) {
    uid = session_extract_sessionid( reply:reply );
    return uid;
  } else {

    if( strlen( reply ) < 34 ) return FALSE;

    low   = ord( reply[32] );
    high  = ord( reply[33] );
    uid   = high * 256;
    uid  += low;
    return uid;
  }
}

# @brief Accepts a SMB reply and extracts the session id. Only call this function when it is an SMB2 reply. See @ref session_extract_uid.
# @note Extract the Session ID from the result of smb_session_setup()
# @param reply The SMB reply that is used.
# @return Returns the id of the session
function session_extract_sessionid( reply ) {

  local_var reply, start, ssid;

  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#session_extract_sessionid" );

  if( strlen( reply ) < 52 ) return FALSE;

  start = stridx( reply, "SMB" ); # TBD: What's the purpose of this? This will be replaced one line below again...
  start = 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 8 + 4 + 4;

  #NTLMSSP challenge is 8 bytes in size
  ssid = ( substr( reply, start, start + 7 ) );
  return ssid;
}


# @brief Accepts a socket and sends an SMB request on this socket. Only older SMB1 dialects are negotiated.
# @note secpod_ms09-001_remote.nasl is the only file using this.
# @param soc The socket that is used for the SMB request.
# @return Returns false if the request fails or returns the received answer.
function smb_neg_prot_cleartext( soc ) {

  # g_mlo and g_mhi are global_vars !!!

  local_var soc, neg_prot, r;

  if( ! soc ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_neg_prot_cleartext" );
    return FALSE;
  }

  #-----------------------------------------------------------------------------------------------------------------------------#
  # This is a special SMB request which request only the following protocols                                                    #
  # PC NETWORK PROGRAM 1.0                                                                                                      #
  # MICROSOFT NETWORKS 1.03                                                                                                     #
  # MICROSOFT NETWORKS 3.0                                                                                                      #
  # LANMAN1.0                                                                                                                   #
  # LM1.2X002                                                                                                                   #
  # Samba                                                                                                                       #
  # After g_mhi 0x00 is the WordCount. 0x66 and 0x00 are the ByteCount the rest is ASCII for the protocols                      #
  # Because it is only used in secpod_ms09-001_remote.nasl my guess is this is explicitly testing for these vulnerable protocols #
  # and has no further use case.                                                                                                #
  #-----------------------------------------------------------------------------------------------------------------------------#

  neg_prot = raw_string( 0x00, 0x00,
                         0x00, 0x89, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
                         0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00,
                         g_mlo, g_mhi, 0x00, 0x66, 0x00, 0x02, 0x50, 0x43,
                         0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B,
                         0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D,
                         0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4D, 0x49,
                         0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54, 0x20,
                         0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53,
                         0x20, 0x31, 0x2E, 0x30, 0x33, 0x00, 0x02, 0x4D,
                         0x49, 0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54,
                         0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B,
                         0x53, 0x20, 0x33, 0x2e, 0x30, 0x00, 0x02, 0x4c,
                         0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30,
                         0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58,
                         0x30, 0x30, 0x32, 0x00, 0x02, 0x53, 0x61, 0x6d,
                         0x62, 0x61, 0x00 );

  send( socket:soc, data:neg_prot );
  r = smb_recv( socket:soc );

  if( strlen( r ) < 10 ) return FALSE;

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Accepts a socket and sends an SMB request on this socket. All SMBv1/2 dialects are offered.
# @note This needs to be extended. It is the main function that is used in the negotiation process.
# @param soc The socket that is used for the SMB request.
# @return Returns NULL if the process fails. Otherwise the received answer is returned as a string.
function smb_neg_prot_NTLMSSP( soc ) {

  # g_mhi, g_mlo, multiplex_id, isSignActive and smb are global_vars!!!

  local_var soc, neg_prot, r, sec_mode, SHA256, port;
  local_var NEGOTIATE_SECURITY_SIGNATURES_ENABLED, NEGOTIATE_SECURITY_SIGNATURES_REQUIRED;
  local_var NEGOTIATE_SECURITY_SIGNATURES_REQUIRED_v2, NEGOTIATE_SECURITY_SIGNATURES_ENABLED_v2;
  # Add more local variables for the support of the preauth features etc.

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_neg_prot_NTLMSSP" );

  # constructing SMB header, also includes the message type and length
  # Construct header according to [MS-CIFS 2.2.3.1]
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;
  neg_prot = raw_string( 0x00, 0x00, 0x00, 0xd4 ); # Netbios message type and length
  neg_prot += raw_string( 0xff, 0x53, 0x4d, 0x42 ); # Protocol ID for SMBv1 header
  neg_prot += raw_string( 0x72 ); # SMB Negotiate Protocol Command
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00 ); # STATUS_SUCCESS
  neg_prot += raw_string( 0x08 ); # Flags: Case Sensitive
  neg_prot += raw_string( 0x01, 0xc8 ); # Flags2
  neg_prot += raw_string( 0x00, 0x00 ); # Process ID High
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Signature
  neg_prot += raw_string( 0x00, 0x00 ); # Reserved
  neg_prot += raw_string( 0xff, 0xff ); # Tree ID
  neg_prot += raw_string( 0x33, 0x0c ); # Process ID
  neg_prot += raw_string( 0x00, 0x00 ); # User ID
  neg_prot += raw_string( g_mlo, g_mhi ); # Multiplex ID

  # Constructing Negotiate Protocol Request --> [MS-CIFS 2.2.4.52.1]
  # We do not need to offer SMBv3.0 because we offer the SMB2 Wildcard

  neg_prot += raw_string( 0x00 ); # Word Count
  neg_prot += raw_string( 0xb1, 0x00 ); # Byte Count

  # Dialect: PC NETWORK PROGRAM 1.0
  neg_prot += raw_string( 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57,
                          0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47,
                          0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30 );
  # Dialect: MICROSOFT NETWORKS 1.03
  neg_prot += raw_string( 0x00, 0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53,
                          0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57,
                          0x4f, 0x52, 0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30,
                          0x33, 0x00 );
  # Dialect: MICROSOFT NETWORKS 3.0
  neg_prot += raw_string( 0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f,
                          0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
                          0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00 );
  # Dialect: LANMAN1.0
  neg_prot += raw_string( 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31,
                          0x2e, 0x30, 0x00 );
  # Dialect: LM1.2X002
  neg_prot += raw_string( 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30,
                          0x30, 0x32, 0x00);
  # Dialect: DOS LANMAN2.1
  neg_prot += raw_string( 0x02, 0x44, 0x4f, 0x53, 0x20, 0x4c, 0x41, 0x4e,
                          0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00 );
  # Dialect: LANMAN2.1
  neg_prot += raw_string( 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32,
                          0x2e, 0x31, 0x00 );
  # Dialect: Samba
  neg_prot += raw_string( 0x02, 0x53, 0x61, 0x6d, 0x62, 0x61, 0x00 );
  # Dialect: NT LANMAN 1.0
  neg_prot += raw_string( 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d,
                          0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00 );
  # Dialect: NT LM 0.12
  neg_prot += raw_string( 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30,
                          0x2e, 0x31, 0x32, 0x00 );
  # Dialect: SMB 2.002
  neg_prot += raw_string( 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30,
                          0x30, 0x32, 0x00 );
  # Dialect: SMB 2.??? (Wildcard)
  neg_prot += raw_string( 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f,
                          0x3f, 0x3f, 0x00 );

  send( socket:soc, data:neg_prot );
  r = smb_recv( socket:soc );
  # Abort if the received answer is too short
  if( strlen( r ) < 38 ) return NULL;

  multiplex_id += 1;

  # Extract the security mode from the received answer
  sec_mode = smb_neg_prot_sm( prot:r );

  # reminder smb is a global variable

  if( sec_mode == 7 ) {
    ##server supports signatured PDUs
    NEGOTIATE_SECURITY_SIGNATURES_ENABLED = TRUE;
  } else if( sec_mode == 15 ) {
    ##server requires signatured PDUs
    NEGOTIATE_SECURITY_SIGNATURES_REQUIRED = TRUE;
    NEGOTIATE_SECURITY_SIGNATURES_ENABLED = TRUE;
  } else if( smb == "SMB2" && sec_mode == 3 ) {
    ##server requires signatured PDUs
    NEGOTIATE_SECURITY_SIGNATURES_REQUIRED_v2 = TRUE;
    NEGOTIATE_SECURITY_SIGNATURES_ENABLED_v2 = TRUE;
  } else if( smb == "SMB2" && sec_mode == 1 ) {
    ##server supports signatured PDUs
    NEGOTIATE_SECURITY_SIGNATURES_ENABLED_v2 = TRUE;
  }

  # Old GVM, where get_smb2_signature function is not present
  # SMB3 requires another check because signing algorithm changed to AES-128-CMAC
  # When was this function introduced maybe it can be removed because the versions are no longer supported
  if( defined_func( 'get_smb2_signature' ) ) {
    SHA256 = TRUE;
  } else {
    SHA256 = FALSE;
  }

  # TBD Should we keep this or can this be cleaned up and removed.
  # Old GVM where get_smb2_signature function is not present, and server requires signatured PDUs only, send smb1 req only
  # On new versions this is all dead code
  # TBD: Test the outcome if this is removed. All older GVM Versions without SHA256 are already long deprecated.
  if( ! SHA256 ) {

    # get_smb2_signature function is not present, send smb1 req only
    if( ( smb == "SMB2" ) && ( NEGOTIATE_SECURITY_SIGNATURES_REQUIRED_v2 && NEGOTIATE_SECURITY_SIGNATURES_ENABLED_v2 ) ) {

      # constructing SMB header, also includes the message type and length
      g_mhi = multiplex_id / 256;
      g_mlo = multiplex_id % 256;
      neg_prot = raw_string( 0x00, 0x00, 0x00, 0xbe,
                             0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
                             0x08, 0x01, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x33,
                             0x0c, 0x00, 0x00, g_mlo, g_mhi );

      # constructing negotiation protocol request
      # Requested Dialects:
      # Dialect: PC NETWORK PROGRAM 1.0
      # Dialect: MICROSOFT NETWORKS 1.03
      # Dialect: MICROSOFT NETWORKS 3.0
      # Dialect: LANMAN1.0
      # Dialect: LM1.2X002
      # Dialect: DOS LANMAN2.1
      # Dialect: LANMAN2.1
      # Dialect: Samba
      # Dialect: NT LANMAN 1.0
      # Dialect: NT LM 0.12

      neg_prot += raw_string( 0x00, 0x9b, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e,
                              0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50,
                              0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31,
                              0x2e, 0x30, 0x00, 0x02, 0x4d, 0x49, 0x43, 0x52,
                              0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45,
                              0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x31,
                              0x2e, 0x30, 0x33, 0x00, 0x02, 0x4d, 0x49, 0x43,
                              0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e,
                              0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20,
                              0x33, 0x2e, 0x30, 0x00, 0x02, 0x4c, 0x41, 0x4e,
                              0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02,
                              0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
                              0x32, 0x00, 0x02, 0x44, 0x4f, 0x53, 0x20, 0x4c,
                              0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31,
                              0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e,
                              0x32, 0x2e, 0x31, 0x00, 0x02, 0x53, 0x61, 0x6d,
                              0x62, 0x61, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c,
                              0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e,
                              0x30, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d,
                              0x20, 0x30, 0x2e, 0x31, 0x32, 0x00 );

      if( soc ) close( soc );

      port = kb_smb_transport();
      if( ! port ) port = 139;

      soc = open_sock_tcp( port );
      if( ! soc ) return NULL;

      send( socket:soc, data:neg_prot );
      r = smb_recv( socket:soc );
      if( strlen( r ) < 38 ) return NULL;

      multiplex_id += 1;

      sec_mode = smb_neg_prot_sm( prot:r );

      if( sec_mode == 7 ) {
        NEGOTIATE_SECURITY_SIGNATURES_ENABLED = TRUE;
      } else if( sec_mode == 15 ) {
        NEGOTIATE_SECURITY_SIGNATURES_REQUIRED = TRUE;
        NEGOTIATE_SECURITY_SIGNATURES_ENABLED = TRUE;
      }

      if( sec_mode && ( NEGOTIATE_SECURITY_SIGNATURES_ENABLED && NEGOTIATE_SECURITY_SIGNATURES_REQUIRED ) ) {
        isSignActive = 1;
      } else {
        isSignActive = 0;
      }

      if( ord( r[9] ) == 0 ) {
        return string( r );
      } else {
        return NULL;
      }
    }

    else if( ( smb == "SMB2" ) && ( ! NEGOTIATE_SECURITY_SIGNATURES_REQUIRED_v2 ) ) {

      isSignActive = 0;

      if( ord( r[12] ) == 0 ) {
        return string( r );
      } else {
        return NULL;
      }
    }

    else if( ( smb != "SMB2" ) && ( NEGOTIATE_SECURITY_SIGNATURES_REQUIRED && NEGOTIATE_SECURITY_SIGNATURES_ENABLED ) ) {

      isSignActive = 1;
      if( ord( r[9] ) == 0 ) {
        return string( r );
      } else {
        return NULL;
      }
    }

    else if( ( smb != "SMB2" ) && ( ! NEGOTIATE_SECURITY_SIGNATURES_REQUIRED ) ) {

      isSignActive = 0;

      if( ord( r[9] ) == 0 ) {
        return string( r );
      } else {
        return NULL;
      }
    }
  }

  # New GVM which supports get_smb2_signature function
  # Relevant Code starts here
  else if( SHA256 ) {

    if( ( sec_mode && ( NEGOTIATE_SECURITY_SIGNATURES_ENABLED && NEGOTIATE_SECURITY_SIGNATURES_REQUIRED ) )||
        ( sec_mode && ( NEGOTIATE_SECURITY_SIGNATURES_REQUIRED_v2 && NEGOTIATE_SECURITY_SIGNATURES_ENABLED_v2 ) ) ) {

      isSignActive = 1;
    } else {
      isSignActive = 0;
    }

    # Check For SMB2
    if( ord( r[4] ) == 254 ) {
      # Return if STATUS_SUCCESS
      if( ord( r[12] ) == 0 ) {
        return string( r );
      }
    }
    ##For SMB1
    else if( ord( r[4] ) == 255 ) {
      # Return if STATUS_SUCCESS
      if( ord( r[9] ) == 0 ) {
        return string( r );
      }
    } else {
      return NULL;
    }
  }
}


# @brief Accepts a socket and sends an SMB request on this socket. Only SMBv1 dialects are offered.
# @note Should not be extended because it does not even support SMBv2 and newer versions use NTLMSSP instead of this.
# @param soc The socket that is used for the SMB request.
# @return Returns NULL if the process fails. Otherwise the received answer is returned as a string.
function smb_neg_prot_NTLMv1( soc ) {

  local_var soc, neg_prot, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_neg_prot_NTLMv1" );

  neg_prot = raw_string( 0x00, 0x00, 0x00, 0xA4, 0xFF, 0x53,
                         0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08,
                         0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x4D, 0x0B, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x81,
                         0x00, 0x02 ) + "PC NETWORK PROGRAM 1.0" +
             raw_string( 0x00, 0x02 ) + "MICROSOFT NETWORKS 1.03" +
             raw_string( 0x00, 0x02 ) + "MICROSOFT NETWORKS 3.0"  +
             raw_string( 0x00, 0x02 ) + "LANMAN1.0" +
             raw_string( 0x00, 0x02 ) + "LM1.2X002" +
             raw_string( 0x00, 0x02 ) + "Samba" +
             raw_string( 0x00, 0x02 ) + "NT LANMAN 1.0" +
             raw_string( 0x00, 0x02 ) + "NT LM 0.12" +
             raw_string( 0x00 );

  send( socket:soc, data:neg_prot );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 38 ) return NULL;

  if( ord( r[9] ) == 0 ) {
    return string( r );
  } else {
    return NULL;
  }
}

# @brief Accepts a socket and calls smb_neg_prot_NTLMv1.
# @note Only use is conficker.nasl
# @param soc The socket that is used for the SMB request.
# @return Returns NULL if the process fails. Otherwise the status of the answer is returned.
function smb_neg_prot_anonymous( soc ) {

  local_var soc;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_neg_prot_anonymous" );

  return smb_neg_prot_NTLMv1( soc:soc );
}

# @brief Accepts a socket and calls smb_neg_prot_NTLMv1 or smb_neg_prot_NTLMSSP if supported.
# @note Main entrypoint for all scripts that rely on smb_login.nasl or need an smb session.
# @param soc The socket that is used for the SMB request.
# @return Returns NULL if the process fails. Otherwise the received answer as a string is returned.
function smb_neg_prot( soc ) {

  local_var soc, res, ntlmsspResult;
  # ntlmssp_flag is global_var!!!

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_neg_prot" );

  if( defined_func( "ntlm2_response" ) ) {
    res = smb_neg_prot_NTLMSSP( soc:soc );
    ntlmsspResult = smb_neg_prot_extract_NTLMSSP( r:res );
    if( ! isnull( ntlmsspResult ) ) {
      ntlmssp_flag = 1;
    } else {
      ntlmssp_flag = 0;
    }
    return res;
  }
  return( smb_neg_prot_NTLMv1( soc:soc ) );
}

# @brief Checks if the server offers NTLMSSP and sets the flag accordingly.
# @note https://www.rfc-editor.org/rfc/rfc4178.html#page-20
#       https://www.rfc-editor.org/rfc/rfc2743.html#page-81
# @param r The received answer.
# @return Returns NULL if the extraction fails. If NTLMSSP is found it returns TRUE.
function smb_neg_prot_extract_NTLMSSP( r ) {

  local_var r, offset, mechTypeListLength, mechTypeLength, blob_len;

  if( isnull( r ) ) return NULL;

  # Checks for SMBv1 or SMBv2 Header format -> Fails otherwise
  if( ord( r[4] ) == 255 ) {
    if( strlen( r ) < 89 ) return NULL; # SMBv1 Answer is too short
    if( ( ord( r[15] ) & 8 ) != 8 ) return NULL; # Extended Security Negotiation is not set
    blob_len = ord( r[71] ) + ord( r[72] ) * 256; # [MS-SMB 2.2.4.5.2.1]
    if( blob_len < 17 ) return NULL; # Verify that the security blob is present by checking the blob length

    offset = 4 + 32 + 53; # Netbios + SMBv1 Header + Negotiate Protocol Request, Offset is fixed

  } else if( ord( r[4] == 254 ) ) {
    if( strlen( r ) < 132 ) return NULL; # Received answer is too short
    blob_len = ord( r[126] ) + ord( r[127] ) * 256; # [MS-SMB2 2.2.4]
    if( blob_len == 0 ) return TRUE; # Client can initiate authentication with a protocol of its choice as GSS-API is not present, NTLMSSP is therefore possible
    offset = 4 + ord( r[124] ) + ord( r[125] ) * 256; # Netbios + the offset mentioned in the message
  } else {
    return NULL;
  }

  # Verify the GSS-API part
  if( ord( r[offset] ) != 96 ) return NULL;
  offset++;
  # We need to check if the length is longer than 128 because than special rules apply
  # https://www.rfc-editor.org/rfc/rfc2743.html#page-81 point 2
  if( ord( r[offset] ) > 128 ) {
    offset += ( ord( r[offset] ) & 127 ) + 1;
  } else {
    offset++;
  }

  if( ord( r[offset] ) != 6 ) return NULL; # No Object Identifier detected
  offset++;
  oid_length = ord( r[offset] );
  if( hexstr( substr( r, offset + 1, offset + oid_length ) ) != "2b0601050502" ) return NULL; # SPNEGO Identifier
  offset = offset + 1 + oid_length;
  if( ord( r[offset] ) != 160 ) return NULL; # NegTokenInit Identifier

  offset++;
  # We need to check if the length is longer than 128 because than special rules apply
  # https://www.rfc-editor.org/rfc/rfc2743.html#page-81 point 2
  if( ord( r[offset] ) > 128 ) {
    offset += ( ord( r[offset] ) & 127 ) + 1;
  } else {
    offset++;
  }

  if( ord( r[offset] ) != 48 ) return NULL; # Check for constructed sequence

  offset++;
  # We need to check if the length is longer than 128 because than special rules apply
  # https://www.rfc-editor.org/rfc/rfc2743.html#page-81 point 2
  if( ord( r[offset] ) > 128 ) {
    offset += ( ord( r[offset] ) & 127 ) + 1;
  } else {
    offset++;
  }

  # No checks for length needed as Microsoft only uses specific protocols
  # The sum of these oids is shorter than 128 Bytes
  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/211417c4-11ef-46c0-a8fb-f178a51c2088#Appendix_A_1
  if( ord( r[offset] ) != 160 ) return NULL; # Identifier Object for the MechTypeList
  offset+=2;
  if( ord( r[offset] ) != 48 ) return NULL; # Check again for constructed sequence
  offset++;
  mechTypeListLength = ord( r[offset] );
  offset++;

  while( mechTypeListLength > 0 ) {
    if( ord( r[offset] ) != 6 ) return NULL; # We do not have an object identifier
    offset++;
    mechTypeLength = ord( r[offset] );
    if( hexstr( substr( r, offset + 1, offset + mechTypeLength ) ) == "2b06010401823702020a" ) {
      return TRUE; # We have found the NTLMSSP identifier
    }
    mechTypeListLength = mechTypeListLength - mechTypeLength;
    offset = offset + 1 + mechTypeLength;
  }

  return NULL;

}

# @brief Accepts a session response and gets the version the server selected.
# @param prot The received SMB answer.
# @return Returns NULL if the process fails. Otherwise the protocol version is returned
function smb_neg_prot_value( prot ) {

  local_var prot, negotiated_prot_l, negotiated_prot_h, value;

  if( isnull( prot ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb_neg_prot_value" );

  if( strlen( prot ) < 38 ) return NULL;

  # Marker that says SMB2 header is used
  # Marker for SMB2 and SMB3
  if( ord( prot[4] ) == 254 ) {
    if( strlen( prot ) < 74 ) return NULL;

    # The specific dialect
    negotiated_prot_l = ord( prot[72] );
    negotiated_prot_h = ord( prot[73] );

    if( negotiated_prot_h ) {
      value = negotiated_prot_h * 256;
      value += negotiated_prot_l;
    } else {
      value = negotiated_prot_l;
    }
    return value;
  } else {
    # If not SMB2 Header return the selected index.
    return( ord( prot[37] ) );
  }
}

# @brief Accepts a session setup response and checks if the communication needs to be encrypted.
# @param prot The received SMBv2 answer.
# @return Returns NULL if the answer is too short. If encryption is supported return TRUE else FALSE.
function smb2_neg_prot_encrypt( prot ) {

  local_var prot;

  if ( isnull ( prot ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb2_neg_prot_encrypt" );

  # This would mean that there is no session setup response attached
  if( strlen( prot ) < 68 ) return NULL;

  # At least hex 0x04 must be set to indicate that encryption is supported.
  if( ord( prot[70] ) > 3 ) {
    return TRUE;
  }
  return FALSE;
}

# @brief Accepts a session response and gets the version the server selected.
# @note Naming is not good. cs is sometimes used in another context. TODO fix this naming
# @param prot The received SMB answer.
# @return Returns NULL if the process fails. Otherwise the protocol version is returned
function smb_neg_prot_cs( prot ) {

  local_var prot;

  if( isnull( prot ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb_neg_prot_cs" );

  if( smb_neg_prot_value( prot:prot ) < 7 ) return NULL;

  if( strlen( prot ) > 80 ) {
    return( substr( prot, 73, 73 + 7 ) );
  } else {
    return NULL ;
  }
}


# @brief Accepts a session response and returns the security mode. Also sets the global string to identify SMB2 header.
# @param prot The received SMB answer.
# @return Returns NULL if the process fails. Otherwise the security mode is returned.
function smb_neg_prot_sm( prot ) {

  # smb is global_var!!!

  local_var prot, sm, sec_mode_hex, sec_mode;

  if( isnull( prot ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb_neg_prot_sm" );

  # Check if at least a base protocol was negotiated
  if( smb_neg_prot_value( prot:prot ) < 7 ) return NULL;

  if( strlen( prot ) < 40 ) return NULL;

  # ord gets the extended ASCII code of prot[4] char
  # determines if it is the SMB2 header or SMB header
  if( ord( prot[4] ) == 254 ) {

    smb = "SMB2";

    if( strlen( prot ) > 70 ) {
      # Returns the 70th character
      sm = substr(prot, 70, 70);
      # Turns the string into ASCII HEX and then decimal
      sec_mode_hex = hexstr(sm);
      sec_mode = hextodec( str:sec_mode_hex );
      return sec_mode;
    }
  } else {
    sm = substr( prot, 39, 39 );
    sec_mode_hex = hexstr( sm );
    sec_mode = hextodec( str:sec_mode_hex );
    return sec_mode;
  }
}

# @brief Seems like it was used to extract a netbios domain from a response
# @note Only usecase in Community Feed is smb_login.nasl where it has been commented so it it not called.
# @param prot The received answer from @ref smb_neg_prot
# @return Returns the netbios domain name.
function smb_neg_prot_domain( prot ) {

  local_var prot, i, ret;
  ret = NULL;

  if( isnull( prot ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb_neg_prot_domain" );

  if( strlen( prot ) < 82 ) return NULL;

  for( i = 81; i < strlen( prot ); i += 2 ) {
    if( ord( prot[i] ) == 0 ) {
      break;
    } else {
      ret += prot[i];
    }
  }
  return ret;
}

# @brief After the protocol negotiation process this functions sets up a session for SMBv1.
# @note Session Setup AndX Request.
# @param soc The socket that is used for the connection.
# @param login The username required for the login.
# @param password The password required for the login.
# @param domain The known Netbios domain for the login.
# @return Returns NULL if it fails or it returns the status code.
function smb_session_setup_cleartext( soc, login, password, domain ) {

  local_var soc, login, password, domain;
  local_var extra, native_os, native_lanmanager, len, bcc;
  local_var len_hi, len_lo, bcc_hi_n, bcc_lo;
  local_var pass_len_hi, pass_len_lo, st;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_session_setup_cleartext" );
  if( isnull( login ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#smb_session_setup_cleartext" );
  if( isnull( password ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#password#-#smb_session_setup_cleartext" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb_session_setup_cleartext" );

  extra = 0;
  native_os = "Unix";
  native_lanmanager = "OpenVAS";

  if( ! domain ) domain = "MYGROUP";

  if( domain ) {
    extra = 3 + strlen( domain ) + strlen( native_os ) + strlen( native_lanmanager );
  } else {
    extra = strlen( native_os ) + strlen( native_lanmanager ) + 2;
  }

  len = strlen( login ) + strlen( password ) + 57 + extra;
  bcc = 2 + strlen( login ) + strlen( password ) + extra;

  len_hi = len / 256;
  len_low = len % 256;

  # Byte Count in Session Setup AndX Request
  bcc_hi = bcc / 256;
  bcc_lo = bcc % 256;

  pass_len = strlen( password ) + 1 ;
  pass_len_hi = pass_len / 256;
  pass_len_lo = pass_len % 256;

  #if (typeof(login) == "int")    display("HORROR! login=", login, "\n");
  #if (typeof(password) == "int") display("HORROR! password=", password, "\n");

  if( ! login ) login = "";
  if( ! password ) password = "";

  st = raw_string( 0x00, 0x00,
                   len_hi, len_low, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00,
                   0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00,
                   0x00, 0x00, 0x0A, 0xFF, 0x00, 0x00, 0x00, 0x04,
                   0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, pass_len_lo, pass_len_hi, 0x00, 0x00, 0x00, 0x00,
                   bcc_lo, bcc_hi ) + password +
       raw_string( 0 ) + login + raw_string( 0x00 );

  if( domain ) st += domain + raw_string( 0x00 );

  st += native_os + raw_string( 0x00 ) + native_lanmanager + raw_string( 0x00 );
  send( socket:soc, data:st );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 10 ) return NULL;

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return NULL;
  }
}

#------------------------NTLMSSP utilities start--------------------------#

# @brief Extracts the NTLM Server Challenge
# @note NTLMSSP extract challenge from type 2 message <-- Previous comment
# @param ret The NTLMSSP response.
# @return The NTLM Server Challenge is returned as a string.
function smb_session_setup_NTLMSSP_extract_chal( ret ) {

  local_var start, ret, cs;

  if( isnull( ret ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ret#-#smb_session_setup_NTLMSSP_extract_chal" );

  start = stridx( ret, "NTLMSSP", 0 );
  start += 8 + 4 + 2 + 2 + 4 + 4; #ntlmssp(8) + message type(4) + domainlen(2) + domain maxlen(2) + offset(4) + flags(4)

  #NTLMSSP challenge is 8 bytes in size
  if( ( strlen( ret ) > 31 ) && ( start ) ) {
    cs = ( substr( ret, start, start + 7 ) );
    return cs;
  }
}

# @brief Extracts the NTLMSSP flags
# @note NTLMSSP extract server flags from type 2 message <-- Previous comment
# @param ret The NTLMSSP response.
# @return The NTLMSSP flags as a decimal value.
function smb_session_setup_NTLMSSP_extract_flag( ret ) {

  local_var start, i, ret;
  local_var flag, serv_flag, server_flag;

  if( isnull( ret ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ret#-#smb_session_setup_NTLMSSP_extract_flag" );

  start = stridx( ret, "NTLMSSP",0 );
  start += 8 + 4 + 2 + 2 + 4; #ntlmssp(8) + message type(4) + domainlen(2) + domain maxlen(2) + offset(4)

  for( i = ( start + 3 ); i > ( start - 1 ); i-- ) {
    serv_flag += ret[i];
  }

  #conversion hex to dec
  server_flag = hexstr( serv_flag );
  flag = hextodec( str:server_flag );
  return flag;
}

# @brief Extracts the NTLMSSP attributes from target info
# @note NTLMSSP extract address list for ntlmv2 auth message <-- Previous comment
#       Extend SecurityBlob until NTLM Secure Service Provider and look into target info to find everything.
# @param ret The NTLMSSP response.
# @return The NTLMSSP attributes as a string or NULL when it fails.
function smb_session_setup_NTLMSSP_extract_addrlist( ret ) {

  local_var start, end, i, ret, addr_list, addrlist_len_str;
  local_var addrlist_offset_str, addrlist_offset;

  if( isnull( ret ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ret#-#smb_session_setup_NTLMSSP_extract_addrlist" );

  start = stridx( ret, "NTLMSSP", 0 );
  # to find address list - length, shift byte positions
  start += 8 + 4; #ntlmssp(8) + message type(4)
  start += 2 + 2 + 4 + 4 + 8 + 8; # domainlen(2) + domain maxlen(2) + offset(4) + flags(4) + challenge(8) + reserved(8);

  addrlist_len_str  = ret[start+1];
  addrlist_len_str += ret[start];
  # Length of field named Target Info with its subfields
  addrlist_len = hextodec( str:( hexstr( addrlist_len_str ) ) );

  # to find address list - offset, shift byte positions
  start += 2 + 2; #address list len(2) + address list max len(2)

  for( i = ( start + 3 ); i > ( start - 1 ); i-- ) {
    addrlist_offset_str += ret[i];
  }

  addrlist_offset = hextodec( str:( hexstr( addrlist_offset_str ) ) );

  # initializing start to the starting position of address list
  start = stridx( ret, "NTLMSSP", 0 ) + addrlist_offset;
  end = start + addrlist_len - 1;

  if( ( strlen( ret ) > end ) && ( start && end ) ) {
    addr_list = substr( ret, start, end );
    return addr_list;
  } else {
    return NULL ;
  }
}

# @brief Gets the extracted flags and converts them if set into a string
# @note NTLMSSP auth flags (based on server flags) <-- Previous comment
# @param neg_flags The flags that have been received and extracted.
# @return A string containing all set flags.
function smb_session_setup_NTLMSSP_auth_flags( neg_flags ) {

  local_var neg_flags, flags, new_server_flags;
  local_var NTLMSSP_NEGOTIATE_UNICODE, NTLMSSP_NEGOTIATE_OEM, NTLMSSP_REQUEST_TARGET, NTLMSSP_NEGOTIATE_SIGN;
  local_var NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_LM_KEY, NTLMSSP_NEGOTIATE_NTLM, NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
  local_var NTLMSSP_NEGOTIATE_NTLM2, NTLMSSP_NEGOTIATE_128, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_56;

  if( isnull( neg_flags ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#neg_flags#-#smb_session_setup_NTLMSSP_auth_flags" );

  NTLMSSP_NEGOTIATE_UNICODE = 0x00000001;
  NTLMSSP_NEGOTIATE_OEM = 0x00000002;
  NTLMSSP_REQUEST_TARGET = 0x00000004;
  NTLMSSP_NEGOTIATE_SIGN = 0x00000010; # Message integrity
  NTLMSSP_NEGOTIATE_SEAL = 0x00000020; # Message confidentiality
  NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080;
  NTLMSSP_NEGOTIATE_NTLM = 0x00000200;
  NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000;
  NTLMSSP_NEGOTIATE_NTLM2 = 0x00080000;
  NTLMSSP_NEGOTIATE_128 = 0x20000000; # 128-bit encryption
  NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000;
  NTLMSSP_NEGOTIATE_56 = 0x80000000;
  flags = 0;

  if( neg_flags & NTLMSSP_NEGOTIATE_UNICODE ) {
    flags += NTLMSSP_NEGOTIATE_UNICODE;
  } else {
    flags += NTLMSSP_NEGOTIATE_OEM;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_LM_KEY ) {
    flags += NTLMSSP_NEGOTIATE_LM_KEY;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN ) {
    flags += NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_NTLM2 ) {
    flags += NTLMSSP_NEGOTIATE_NTLM2;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_128 ) {
    flags += NTLMSSP_NEGOTIATE_128;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_56 ) {
    flags += NTLMSSP_NEGOTIATE_56;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH ) {
    flags += NTLMSSP_NEGOTIATE_KEY_EXCH;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_SIGN ) {
    flags += NTLMSSP_NEGOTIATE_SIGN;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_SEAL ) {
    flags += NTLMSSP_NEGOTIATE_SEAL;
  }

  if( neg_flags & NTLMSSP_NEGOTIATE_NTLM ) {
    flags += NTLMSSP_NEGOTIATE_NTLM;
  }

  if( neg_flags & NTLMSSP_REQUEST_TARGET ) {
    flags += NTLMSSP_REQUEST_TARGET;
  }

  new_server_flags = dec2str( num:flags );

  return new_server_flags;
}
#------------------------NTLMSSP utilities end----------------------------#


#--------------------NTLMSSP IMPLEMENTATION START-------------------------------------------------#
#-------------------------------------------------------------------------------------------------#

# @brief Negotiates protocols using the SMB2 header.
# @note NTLM SSP NEGOTIATION SMB2 <-- Previous comment
#       Maybe instead of plain hex codes more variables could be used.
# @param soc The socket used for the connection.
# @return The received response of the protocol negotiation request.
function smb2_neg_prot( soc ) {

  # those are global_vars!!!
  multiplex_id = 1;
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  local_var soc, neg_prot, len, len_hi, len_lo, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2_neg_prot" );

  client_guid = bn_random( need:8*16 ); # Client GUID
  # Somehow bn_random has weird bug where the returned number is too small
  while( strlen( client_guid ) < 16 ) {
    client_guid = bn_random( need:8*16 );
  }

  #SMB2 header according to [MS-SMB2 2.2.1.2]
  neg_prot = raw_string( 0xfe, 0x53, 0x4d, 0x42 ); # Protocol Identifier
  neg_prot += raw_string( 0x40, 0x00 ); # Structure Size
  neg_prot += raw_string( 0x01, 0x00 ); # CreditCharge
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Status
  neg_prot += raw_string( 0x00, 0x00 ); # Negotiate Protocol Command
  neg_prot += raw_string( 0x00, 0x00 ); # Credit Request
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Flags
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Next Command --> Compound Request
  neg_prot += raw_string( g_mlo, g_mhi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Message ID
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Reserved
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00 ); # TreeID
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # SessionID
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Signature

  # SMB2 Negotiate Request according to [MS-SMB2 2.2.3]
  neg_prot += raw_string( 0x24, 0x00 ); # Structure Size

  if( defined_func( 'smb3kdf' ) ) {
    neg_prot += raw_string( 0x04, 0x00 ); # Dialect Count
  } else {
    neg_prot += raw_string( 0x02, 0x00 ); # Dialect Count
  }

  neg_prot += raw_string( 0x01, 0x00 ); # Security Mode
  neg_prot += raw_string( 0x00, 0x00 ); # Reserved
  neg_prot += raw_string( 0x40, 0x00, 0x00, 0x00 ); # Capabilities --> Encryption
  neg_prot += client_guid; # Client GUID
  neg_prot += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Different depending on dialect
  neg_prot += raw_string( 0x02, 0x02 ); # SMB 2.0.2
  neg_prot += raw_string( 0x10, 0x02 ); # SMB 2.1

  if( defined_func( 'smb3kdf' ) ) {
    neg_prot += raw_string( 0x00, 0x03 ); # SMB 3.0
    neg_prot += raw_string( 0x02, 0x03 ); # SMB 3.0.2
  }
  # TBD add more dialects

  len = strlen( neg_prot );
  len_hi = len / 256;
  len_lo = len % 256;

  neg_prot = raw_string( 0x00, 0x00, len_hi, len_lo ) + neg_prot;

  send( socket:soc, data:neg_prot );
  r = smb_recv( socket:soc );
  multiplex_id += 1;
  if( r ) return r;
}

# @brief Creates the NTMLSSP Session Setup Request NTLMSSP_NEGOTIATE for the SMB Header
# @note SMB <-- Previous comment
# @param soc The socket used for the connection.
# @param domain The netbios domain name.
# @return Returns the received answer or FALSE in case something goes wrong.
function smb_session_setup_NTLMSSP_NEGOT( soc, domain ) {

  # g_mhi, g_mlo, multiplex_id and isSignActive are global_vars!!!
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  local_var soc, domain, st, wsdomain, wsname, wsdomlen, wsnmlen, wsdomainoff, wsnameoff, wsdomain_hi, wsdomain_lo;
  local_var wsname_hi, wsname_lo, wsdomoffset_hi, wsdomoffset_lo, wsname_hi, wsname_lo, wsnameoffset_hi, wsnameoffset_lo;
  local_var wsdomainlen, wsnamelen, wsdomainoffset, wsnameoffset;
  local_var os, native_os, lanman, native_lanmanager, ntlmssp;
  local_var ntlmssplen, mechToken, mechType, negTokenInit, spnegolen, spnego, oid, gsslen, sec_blob_length_hi, sec_blob_length_lo;
  local_var byte_count_hi, byte_count_lo, secblob, stt, r, len, len_hi, len_low;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_session_setup_NTLMSSP_NEGOT" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb_session_setup_NTLMSSP_NEGOT" );

  #SMB header
  st = raw_string( 0xff, 0x53, 0x4d, 0x42, 0x73, 0x00, 0x00, 0x00,
                   0x00, 0x08 );

  if( isSignActive ) {
    st +=  raw_string( 0x05, 0xc8 );
  } else {
    st += raw_string( 0x01, 0xc8 );
  }

  st += raw_string( 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x33, 0x0c, 0x00, 0x00, g_mlo, g_mhi );

  #Session Setup AndX Request
  st += raw_string( 0x0c, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x02,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 );

  wsdomain = domain;
  wsname = "HostName";
  wsdomlen = strlen( wsdomain );
  wsnmlen = strlen( wsname );
  wsdomainoff = 32;
  wsnameoff = 32 + wsdomlen;

  wsdomain_hi = wsdomlen / 256;
  wsdomain_lo = wsdomlen % 256;

  wsname_hi = wsnmlen / 256;
  wsname_lo = wsnmlen % 256;

  wsdomoffset_hi = wsdomainoff / 256;
  wsdomoffset_lo = wsdomainoff % 256;

  wsnameoffset_hi = wsnameoff / 256;
  wsnameoffset_lo = wsnameoff % 256;

  wsdomainlen = raw_string( wsdomain_lo ) + raw_string( wsdomain_hi ); # length 2 bytes
  wsnamelen = raw_string( wsname_lo ) + raw_string( wsname_hi ); # length 2 bytes
  wsdomainoffset = raw_string( wsdomoffset_lo ) + raw_string( wsdomoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes
  wsnameoffset = raw_string( wsnameoffset_lo ) + raw_string( wsnameoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  os = "Unix";
  native_os = insert_hexzeros( in:os );
  lanman = "OpenVAS";
  native_lanmanager = insert_hexzeros( in:lanman );

  # Creating NTLMSSP in Security Blob for the request

  # raw string contains NTLMSSP: sign, type1 msgtype, flags
  #flags: ntlm2+keyex(0x60088215), ntlm+keyex(0x60008215), ntlm2(0x20088215), ntlm(0x20008215)
  ntlmssp = raw_string( 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x60 );

  #adding workstation domain - length,maxLen,offset and workstation name - length,maxLen,offset
  ntlmssp += wsdomainlen + wsdomainlen + wsdomainoffset + wsnamelen + wsnamelen + wsnameoffset;

  # adding workstation domain
  if( wsdomain ) ntlmssp += toupper( wsdomain );

  #adding workstation name
  ntlmssp += toupper( wsname );

  ntlmssplen = ( 16 + 16 + strlen( wsdomain ) + strlen( wsname ) );
  mechToken = raw_string( 0xa2 ) + raw_string( ntlmssplen + 2 ) + raw_string( 0x04 ) + raw_string( ntlmssplen );

  #mechType offset 10, value 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
  mechType = raw_string( 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
                         0x37, 0x02, 0x02, 0x0a );

  #Nogotiation Token Init : 0xa0 negTokenInit Identifier, offset 15, 0x30 seq identifier, offset 12
  negTokenInit = raw_string( 0xa0, 0x0e, 0x30, 0x0c );

  spnegolen = 4 + 12 + 4 + ntlmssplen;
  spnego = raw_string( 0xa0 ) + raw_string( spnegolen + 2 ) + raw_string( 0x30 ) + raw_string( spnegolen );

  # identifier and OID 1.3.6.1.5.5.2 (SPNEGO)
  oid =  raw_string( 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 );

  gsslen = 8 + 4 + spnegolen;

  sec_blob_length_hi = ( gsslen + 2 ) / 256;
  sec_blob_length_lo = ( gsslen + 2 ) % 256;

  byte_count_hi = ( gsslen + 2 + strlen( native_os ) + 2 + strlen( native_lanmanager ) + 2 ) / 256;
  byte_count_lo = ( gsslen + 2 + strlen( native_os ) + 2 + strlen( native_lanmanager ) + 2 ) % 256;

  #Creating Security Blob for the request
  secblob = raw_string( 0x60 ) + raw_string( gsslen ) + oid + spnego + negTokenInit + mechType + mechToken + ntlmssp;

  #appending security blob length to the request
  st += raw_string( sec_blob_length_lo ) + raw_string( sec_blob_length_hi );

  #appending reserved and capabilities to the request
  st += raw_string( 0x00, 0x00, 0x00, 0x00, 0x5c, 0xc0, 0x00, 0x80 );

  #appending byte count to the request
  st += raw_string( byte_count_lo ) + raw_string( byte_count_hi );

  #appending security blob, nativeOS, nativeLanManager
  st += secblob + native_os + raw_string( 0x00, 0x00 ) + native_lanmanager + raw_string( 0x00, 0x00 );

  #length of entire packet
  len = strlen( st );
  len_hi = len / 256;
  len_lo = len % 256;

  stt = raw_string( 0x00, 0x00, len_hi, len_lo ) + st;

  send( socket:soc, data:stt );
  r = smb_recv(socket:soc);
  if( strlen( r ) < 10 ) return FALSE;

  multiplex_id += 1;

  if( ord( r[9] ) == 22 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Creates the NTLMSSP Sessions Setup Request NTLMSSP_NEGOTIATE for the SMBv2 Header
# @note SMB2 <-- Previous comment
# @param soc The socket used for the connection.
# @param domain The netbios domain name.
# @return Returns the received answer or FALSE in case something goes wrong.
function smb2_session_setup_NTLMSSP_NEGOT( soc, domain ) {

  # g_mhi, g_mlo, multiplex_id and isSignActive are global_vars!!!
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  local_var soc, domain, st, wsdomain, wsname, wsdomlen, wsnmlen, wsdomainoff, wsnameoff, wsdomain_hi, wsdomain_lo, wsname_hi, wsname_lo;
  local_var wsdomoffset_hi, wsdomoffset_lo, wsnameoffset_hi, wsnameoffset_lo, wsname_hi, wsname_lo;
  local_var wsdomainlen, wsnamelen, wsdomainoffset, wsnameoffset;
  local_var os, native_os, lanman, native_lanmanager, ntlmssp;
  local_var ntlmssplen, mechToken, mechType, negTokenInit, spnegolen, spnego, oid, gsslen, sec_blob_length_hi, sec_blob_length_lo;
  local_var secblob, secblob_len, secblob_len_hi, secblob_len_lo, len, len_hi, len_lo, stt, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2_session_setup_NTLMSSP_NEGOT" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb2_session_setup_NTLMSSP_NEGOT" );

  #SMB2 header [MS-SMB2 2.2.1.2]
  st = raw_string( 0xfe, 0x53, 0x4d, 0x42 ); # Protocol ID
  st += raw_string( 0x40, 0x00 ); # Structure Size
  st += raw_string( 0x01, 0x00 ); # Credit Charge
  st += raw_string( 0x00, 0x00, 0x00, 0x00 ); # ChannelSequence, Reserved, Status
  st += raw_string( 0x01, 0x00 ); # Command --> Session Setup
  st += raw_string( 0x00, 0x00 ); # Credit request
  st += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Flags
  st += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Next Command
  st += raw_string( g_mlo, g_mhi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Message ID
  st += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Reserved
  st += raw_string( 0x00, 0x00, 0x00, 0x00 ); # TreeID
  st += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # SessionID
  st += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Signature

  #Session Setup Request [MS-SMB2 2.2.5]
  st += raw_string( 0x19, 0x00 ); # Structure Size
  st += raw_string( 0x00 ); # Flags
  st += raw_string( 0x01 ); # Security Mode
  st += raw_string( 0x40, 0x00, 0x00, 0x00 ); # Capabilities
  st += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Channel
  st += raw_string( 0x58, 0x00 ); # Security Buffer Offset

  wsdomain = domain;
  wsname = "";
  wsdomlen = strlen( wsdomain );
  wsnmlen = strlen( wsname );
  wsdomainoff = 32;
  wsnameoff = 32 + wsdomlen;

  wsdomain_hi = wsdomlen / 256;
  wsdomain_lo = wsdomlen % 256;

  wsname_hi = wsnmlen / 256;
  wsname_lo = wsnmlen % 256;

  wsdomoffset_hi = wsdomainoff / 256;
  wsdomoffset_lo = wsdomainoff % 256;

  wsnameoffset_hi = wsnameoff / 256;
  wsnameoffset_lo = wsnameoff % 256;

  wsdomainlen = raw_string( wsdomain_lo ) + raw_string( wsdomain_hi ); # length 2 bytes
  wsnamelen = raw_string( wsname_lo ) + raw_string( wsname_hi ); # length 2 bytes
  wsdomainoffset = raw_string( wsdomoffset_lo ) + raw_string( wsdomoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes
  wsnameoffset = raw_string( wsnameoffset_lo ) + raw_string( wsnameoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  os = "Unix";
  native_os = insert_hexzeros( in:os );
  lanman = "OpenVAS";
  native_lanmanager = insert_hexzeros( in:lanman );

  #Creating NTLMSSP in Security Blob for the request
  #raw string contains NTLMSSP: sign, type1 msgtype, flags
  #flags: ntlm2+keyex(0x60088215), ntlm+keyex(0x60008215), ntlm2(0x20088215), ntlm(0x20008215)

  ntlmssp = raw_string( 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x60 );

  #adding workstation domain - length,maxLen,offset and workstation name - length,maxLen,offset
  ntlmssp += wsdomainlen + wsdomainlen + wsdomainoffset + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
  # raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

  # adding workstation domain
  if( wsdomain ) ntlmssp += toupper( wsdomain );

  #adding workstation name
  # ntlmssp += toupper( wsname );

  ntlmssplen = strlen( ntlmssp );
  mechToken = raw_string( 0xa2 ) + raw_string( ntlmssplen + 2 ) + raw_string( 0x04 ) + raw_string( ntlmssplen );

  #mechType offset 10, value 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
  mechType =  raw_string( 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
                          0x37, 0x02, 0x02, 0x0a );

  #Nogotiation Token Init : 0xa0 negTokenInit Identifier, offset 15, 0x30 seq identifier, offset 12
  negTokenInit = raw_string( 0xa0, 0x0e, 0x30, 0x0c );

  spnegolen = 4 + 12 + 4 + ntlmssplen;
  spnego = raw_string( 0xa0 ) + raw_string( spnegolen + 2 ) + raw_string( 0x30 ) + raw_string( spnegolen );

  # identifier and OID 1.3.6.1.5.5.2 (SPNEGO)
  oid =  raw_string( 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 );

  gsslen = 8 + 4 + spnegolen;
  sec_blob_length_hi = ( gsslen + 2 ) / 256;
  sec_blob_length_lo = ( gsslen + 2 ) % 256;

  #Creating Security Blob for the request
  secblob = raw_string( 0x60 ) + raw_string( gsslen ) + oid + spnego + negTokenInit + mechType + mechToken + ntlmssp;

  secblob_len = strlen( secblob );
  secblob_len_hi = secblob_len / 256;
  secblob_len_lo = secblob_len % 256;

  #appending security blob length to the request
  st += raw_string( secblob_len_lo + secblob_len_hi ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
  st += secblob;

  #length of entire packet
  len = strlen( st );
  len_hi = len / 256;
  len_lo = len % 256;

  stt = raw_string( 0x00, 0x00, len_hi, len_lo ) + st;

  send( socket:soc, data:stt );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 13 ) return FALSE;

  multiplex_id += 1;

  ##More Processing required == 0x16 == 22
  if( ord( r[12] ) == 22 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Creates the Session Setup Request NTLMSSP_AUTH for a SMBv1 header.
# @param soc The socket that is used for the communication.
# @param login The username that is used to login.
# @param password The password that is used to login.
# @param domain The Netbios domain name.
# @param version The NTLM version that should be used.
# @param cs The challenge from the server.
# @param uid The session id.
# @param server_flags All information regarding the flags set by the server.
# @param flag_str All active server flags as a string.
# @param addr_list The extracted attributes regarding the target. See @ref smb_session_setup_NTLMSSP_extract_addrlist.
# @return Returns the received answer or FALSE in case something goes wrong.
function smb_session_setup_NTLMSSP_AUTH( soc, login, password, domain, version, cs, uid, server_flags, flag_str, addr_list ) {

  # s_sign_key, sign_key, g_mhi, g_mlo, multiplex_id and seq_number are global_vars!!!

  local_var soc, login, password, domain, version, cs, uid, server_flags, flag_str, addr_list;
  local_var NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_NTLM2;
  local_var st, uid_hi, uid_lo, NT_H, ntlmv2_hash, result, lm, nt, session_key, encrypted_session_key;
  local_var lm_resplen, ntlm_resplen, lmoff, ntlmoff, lm_resp_hi, lm_resp_lo, ntlm_resp_hi, ntlm_resp_lo;
  local_var lm_resp_length, ntlm_resp_length, lm_resp_offset, ntlm_resp_offset;
  local_var workstname, user, username;
  local_var wsdomain, wsname, wsdomlen, wsnmlen, usernmlen, wsdomainoff, usernameoff, wsnameoff;
  local_var wsdomain_hi, wsdomain_lo, wsname_hi, wsname_lo, username_hi, username_lo;
  local_var wsdomoffset_hi, wsdomoffset_lo, wsnameoffset_hi, wsnameoffset_lo;
  local_var usernameoffset_hi, usernameoffset_lo, wsdomainlen, wsnamelen, usernamelen;
  local_var wsdomainoffset, wsnameoffset, usernameoffset;
  local_var sec_key_len, sec_key_off, seckey_hi, seckey_lo, seckeyoff_hi, seckeyoff_lo;
  local_var seckeylength, seckeyoffset, os, native_os, lanman, native_lanmanager;
  local_var len, len_hi, len_lo, secblob, secbloblen, ntlmssp, ntlmssplen;
  local_var secbloblen_hi, secbloblen_lo, bytecount, bytecount_hi, bytecount_lo;
  local_var stt, req, r, server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( login ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( password ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#password#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( version ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( cs ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cs#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( server_flags ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#server_flags#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( flag_str ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#flag_str#-#smb_session_setup_NTLMSSP_AUTH" );
  if( isnull( addr_list ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#addr_list#-#smb_session_setup_NTLMSSP_AUTH" );

  if( ! domain ) domain = "WORKGROUP";

  NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000;
  NTLMSSP_NEGOTIATE_NTLM2 = 0x00080000;

  #SMB header
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;
  st = raw_string( 0xff, 0x53, 0x4d, 0x42, 0x73,
                   0x00, 0x00, 0x00, 0x00, 0x08 );

  if( isSignActive ) {
    st += raw_string( 0x05, 0xc8 );
  } else {
    st += raw_string( 0x01, 0xc8 );
  }

  st += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x0c );

  #user id
  uid_hi = uid / 256;
  uid_lo = uid % 256;
  st += raw_string( uid_lo ) + raw_string( uid_hi );

  #multiplex id
  st += raw_string( g_mlo, g_mhi );

  if( version == 2 ) {

    #nt hash
    NT_H = nt_owf_gen( password );
    if( isnull( NT_H ) ) return FALSE;

    ntlmv2_hash = ntv2_owf_gen( owf:NT_H, login:login, domain:domain );
    if( isnull( ntlmv2_hash ) ) return FALSE;

    addr_list_len = strlen( addr_list );
    result = ntlmv2_response( cryptkey:cs, user:login, domain:domain, ntlmv2_hash:ntlmv2_hash, address_list:addr_list, address_list_len:addr_list_len );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 40 ) {
      lm = substr( result, 0, 23 );
      session_key = substr( result, 24, 39 );
      nt = substr( result, 40, strlen( result ) - 1 );
    }
  } else if( server_flags & NTLMSSP_NEGOTIATE_NTLM2 ) {

    #nt hash
    NT_H = nt_owf_gen( password );
    if( isnull( NT_H ) ) return FALSE;

    result = ntlm2_response( cryptkey:cs, password:password, nt_hash:NT_H );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 63 ) {
      lm = substr( result, 0, 23 );
      nt = substr( result, 24, 47 );
      session_key = substr( result, 48, 63 );
    }
  } else {

    #nt hash
    NT_H = nt_owf_gen( password );
    if( isnull( NT_H ) ) return FALSE;

    result = ntlm_response( cryptkey:cs, password:password, nt_hash:NT_H, neg_flags:server_flags );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 63 ) {
      lm = substr( result, 0, 23 );
      nt = substr( result, 24, 47 );
      session_key = substr(result, 48, 63);
    }
  }

  if( server_flags & NTLMSSP_NEGOTIATE_KEY_EXCH ) {
    result = key_exchange( cryptkey:cs, session_key:session_key, nt_hash:NT_H );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 31 ) {
      session_key = substr( result, 0, 15 );
      encrypted_session_key = substr( result, 16, 31 );
    }
  }

  s_sign_key = session_key;
  lm_resplen = strlen( lm );
  ntlm_resplen = strlen( nt );
  lmoff = 64;
  ntlmoff = lmoff + lm_resplen;

  lm_resp_hi = lm_resplen / 256;
  lm_resp_lo = lm_resplen % 256;

  ntlm_resp_hi = ntlm_resplen / 256;
  ntlm_resp_lo = ntlm_resplen % 256;

  lmoff_hi = lmoff / 256;
  lmoff_lo = lmoff % 256;

  ntlmoff_hi = ntlmoff / 256;
  ntlmoff_lo = ntlmoff % 256;

  lm_resp_length = raw_string( lm_resp_lo ) + raw_string( lm_resp_hi ); # length 2 bytes
  ntlm_resp_length = raw_string( ntlm_resp_lo ) + raw_string( ntlm_resp_hi ); # length 2 bytes
  lm_resp_offset = raw_string( lmoff_lo ) + raw_string( lmoff_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes
  ntlm_resp_offset = raw_string( ntlmoff_lo ) + raw_string( ntlmoff_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  workstname = "HostName";
  user = login;

  username = insert_hexzeros( in:login );
  wsdomain = insert_hexzeros( in:domain );
  wsname = insert_hexzeros( in:workstname );

  wsdomlen = ( strlen( wsdomain ) );
  wsnmlen = (strlen( wsname ) );
  usernmlen = ( strlen( username ) );

  wsdomainoff = ntlmoff + ntlm_resplen;
  usernameoff = wsdomainoff + wsdomlen;
  wsnameoff = usernameoff + usernmlen;

  wsdomain_hi = wsdomlen / 256;
  wsdomain_lo = wsdomlen % 256;

  wsname_hi = wsnmlen / 256;
  wsname_lo = wsnmlen % 256;

  username_hi = usernmlen / 256;
  username_lo = usernmlen % 256;

  wsdomoffset_hi = wsdomainoff / 256;
  wsdomoffset_lo = wsdomainoff % 256;

  wsnameoffset_hi = wsnameoff / 256;
  wsnameoffset_lo = wsnameoff % 256;

  usernameoffset_hi = usernameoff / 256;
  usernameoffset_lo = usernameoff % 256;

  wsdomainlen = raw_string( wsdomain_lo ) + raw_string( wsdomain_hi ); # length 2 bytes
  wsnamelen = raw_string( wsname_lo ) + raw_string( wsname_hi ); # length 2 bytes
  usernamelen = raw_string( username_lo ) + raw_string( username_hi ); # length 2 bytes
  wsdomainoffset = raw_string( wsdomoffset_lo ) + raw_string( wsdomoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes
  wsnameoffset = raw_string( wsnameoffset_lo ) + raw_string( wsnameoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes
  usernameoffset = raw_string( usernameoffset_lo ) + raw_string( usernameoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  # encrypted session key
  sec_key_len = 16;
  sec_key_off = wsnameoff + wsnmlen;

  seckey_hi = sec_key_len / 256;
  seckey_lo = sec_key_len % 256;
  seckeyoff_hi = sec_key_off / 256;
  seckeyoff_lo = sec_key_off % 256;

  seckeylength = raw_string( seckey_lo ) + raw_string( seckey_hi ); # length 2 bytes
  seckeyoffset = raw_string( seckeyoff_lo ) + raw_string( seckeyoff_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  os = "Unix";
  native_os = insert_hexzeros( in:os );
  lanman = "OpenVAS";
  native_lanmanager = insert_hexzeros( in:lanman );

  #Creating NTLMSSP in Security Blob for the request

  # raw string contains NTLMSSP: sign, type1 msgtype, flags
  ntlmssp = raw_string( 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53,
                        0x50, 0x00, 0x03, 0x00, 0x00, 0x00 ) +
            lm_resp_length + lm_resp_length + lm_resp_offset +
            ntlm_resp_length + ntlm_resp_length + ntlm_resp_offset +
            wsdomainlen + wsdomainlen + wsdomainoffset +
            usernamelen + usernamelen + usernameoffset +
            wsnamelen + wsnamelen + wsnameoffset +
            seckeylength + seckeylength + seckeyoffset +
            flag_str;

  #adding NT LM Challenge response
  ntlmssp += lm + nt;

  # adding workstation domain
  if( wsdomain ) ntlmssp += toupper( wsdomain );

  #adding username
  ntlmssp += toupper( username );

  #adding workstation name
  ntlmssp += toupper( wsname );

  #adding session key
  ntlmssp += encrypted_session_key;

  #NTLMSSP length
  ntlmssplen = 64 + lm_resplen + ntlm_resplen + wsdomlen + wsnmlen + usernmlen + sec_key_len;

  #Security Blob
  if( version == 2 ) {

    len = ntlmssplen + 12;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob = raw_string( 0xa1, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo );
    len = ntlmssplen + 8;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob += raw_string( 0x30, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo );
    len = ntlmssplen + 4;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob += raw_string( 0xa2, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo );
    len = ntlmssplen;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob += raw_string( 0x04, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo ) + ntlmssp;
    secbloblen = 16 + ntlmssplen;

  } else {

    secblob = raw_string( 0xa1, 0x81 ) + raw_string( ntlmssplen + 9 ) +
              raw_string( 0x30, 0x81 ) + raw_string( ntlmssplen + 6 ) +
              raw_string( 0xa2, 0x81 ) + raw_string( ntlmssplen + 3 ) +
              raw_string( 0x04, 0x81 ) + raw_string( ntlmssplen ) + ntlmssp;
              secbloblen = 12 + ntlmssplen;
  }

  secbloblen_hi = secbloblen / 256;
  secbloblen_lo = secbloblen % 256;
  bytecount = secbloblen + 1 + strlen( native_os ) + 2 + strlen( native_lanmanager ) + 2;
  bytecount_hi = bytecount / 256;
  bytecount_lo = bytecount % 256;

  #Session Setup AndX Request
  st += raw_string( 0x0c, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x02,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 );
  st += raw_string( secbloblen_lo ) + raw_string( secbloblen_hi ) +
        raw_string( 0x00, 0x00, 0x00, 0x00, 0x5c, 0xc0, 0x00, 0x80 ) + # reserved and capabilities
        raw_string( bytecount_lo ) + raw_string( bytecount_hi ) +
        secblob + raw_string( 0x00 ) + native_os + raw_string( 0x00, 0x00 ) + native_lanmanager + raw_string( 0x00, 0x00 );

  #length of entire packet
  len = strlen( st );
  len_hi = len / 256;
  len_lo = len % 256;

  stt = raw_string( 0x00, 0x00, len_hi, len_lo ) + st;

  if( isSignActive ) {
    len += 4;
    seq_number = 0;
    req = get_signature( key:s_sign_key, buf:stt, buflen:len, seq_number:seq_number );
    if( isnull( req ) ) return FALSE;
  } else {
    req = stt;
  }

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 10 ) return FALSE;

  multiplex_id += 1;

  if( r && isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) return FALSE;

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Creates the Session Setup Request NTLMSSP_AUTH for a SMBv2 header.
# @note SMB2 NTLMSSP AUTHENTICATION <-- Previous comment
# @param soc The socket that is used for the communication.
# @param login The username that is used to login.
# @param password The password that is used to login.
# @param domain The Netbios domain name.
# @param version The NTLM version that should be used.
# @param cs The challenge from the server.
# @param ssid The session id.
# @param server_flags All information regarding the flags set by the server.
# @param flag_str All active server flags as a string.
# @param addr_list The extracted attributes regarding the target. See @ref smb_session_setup_NTLMSSP_extract_addrlist.
# @return Returns the received answer or FALSE in case something goes wrong.
function smb2_session_setup_NTLMSSP_AUTH( soc, login, password, domain, version, cs, ssid, server_flags, flag_str, addr_list ) {

  # s_sign_key, sign_key, g_mhi, g_mlo, multiplex_id and seq_number are global_vars!!!

  local_var soc, login, password, domain, version, cs, ssid, server_flags, flag_str, addr_list;
  local_var NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_NTLM2;
  local_var st, NT_H, ntlmv2_hash, addr_list_len, result, lm, session_key, nt, encrypted_session_key;
  local_var lm_resplen, ntlm_resplen, lmoff, ntlmoff, lm_resp_hi, lm_resp_lo;
  local_var ntlm_resp_hi, ntlm_resp_lo, lmoff_hi, lmoff_lo, ntlmoff_hi, ntlmoff_lo;
  local_var lm_resp_length, ntlm_resp_length, lm_resp_offset, ntlm_resp_offset;
  local_var workstname, user, username, wsdomain, wsname, wsdomlen, wsnmlen, usernmlen, wsdomainoff;
  local_var usernameoff, wsnameoff, wsdomain_hi, wsdomain_lo, wsname_hi, wsname_lo, username_hi;
  local_var username_lo, wsdomoffset_hi, wsdomoffset_lo, wsnameoffset_hi, wsnameoffset_lo;
  local_var usernameoffset_hi, usernameoffset_lo, wsdomainlen, wsnamelen, usernamelen;
  local_var usernameoffset, wsdomainoffset, wsnameoffset, sec_key_len, sec_key_off, seckey_hi, seckey_lo;
  local_var seckeyoff_hi, seckeyoff_lo, seckeylength, seckeyoffset;
  local_var os, native_os, lanman, native_lanmanager, ntlmssp, ntlmssplen;
  local_var len, len_hi, len_lo, secblob, secbloblen, secbloblen_hi, secbloblen_lo;
  local_var bytecount, bytecount_hi, bytecount_lo, stt, req, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( login ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( password ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#password#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( version ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( cs ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cs#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( ssid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ssid#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( server_flags ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#server_flags#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( flag_str ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#flag_str#-#smb2_session_setup_NTLMSSP_AUTH" );
  if( isnull( addr_list ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#addr_list#-#smb2_session_setup_NTLMSSP_AUTH" );

  if( ! domain ) domain = "WORKGROUP";

  NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000;
  NTLMSSP_NEGOTIATE_NTLM2 = 0x00080000;

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  #SMB2 header
  st = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x01, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   g_mlo, g_mhi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00 );

  #Add Session ID
  st += raw_string( ssid );

  #Signature
  st += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  #if( isSignActive ) {
  #  st += raw_string( 0x05, 0xc8 );
  #} else {
  #  st += raw_string( 0x19, 0x00 );
  #}

  if( version == 2 ) {

    #nt hash
    NT_H = nt_owf_gen( password );
    if( isnull( NT_H ) ) return FALSE;

    ntlmv2_hash = ntv2_owf_gen( owf:NT_H, login:login, domain:domain );
    if( isnull( ntlmv2_hash ) ) return FALSE;

    addr_list_len = strlen( addr_list );
    result = ntlmv2_response( cryptkey:cs, user:login, domain:domain, ntlmv2_hash:ntlmv2_hash, address_list:addr_list, address_list_len:addr_list_len );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 40 ) {
      lm = substr( result, 0, 23 );
      session_key = substr( result, 24, 39 );
      nt = substr( result, 40, strlen( result ) - 1 );
    }
  } else if( server_flags & NTLMSSP_NEGOTIATE_NTLM2 ) {

    #nt hash
    NT_H = nt_owf_gen( password );
    if( isnull( NT_H ) ) return FALSE;

    result = ntlm2_response( cryptkey:cs, password:password, nt_hash:NT_H );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 63 ) {
      lm = substr( result, 0, 23 );
      nt = substr( result, 24, 47 );
      session_key = substr( result, 48, 63 );
    }
  } else {

    #nt hash
    NT_H = nt_owf_gen( password );
    if( isnull( NT_H ) ) return FALSE;

    result = ntlm_response( cryptkey:cs, password:password, nt_hash:NT_H, neg_flags:server_flags );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 63 ) {
      lm = substr( result, 0, 23 );
      nt = substr( result, 24, 47 );
      session_key = substr( result, 48, 63 );
    }
  }

  s_sign_key = session_key;

  if( server_flags & NTLMSSP_NEGOTIATE_KEY_EXCH ) {

    result = key_exchange( cryptkey:cs, session_key:session_key, nt_hash:NT_H );
    if( isnull( result ) ) return FALSE;

    if( strlen( result ) > 31 ) {
      # TBD: evaluate if this is the full session key that is needed for AES-256-CCM/GCM mode
      session_key = substr( result, 0, 15 );
      encrypted_session_key = substr( result, 16, 31 );

      ## session_key is used as signing key when using smbv2 --> smbv3 needs to compute keys
      ## compute_keys handles both cases
      ## signing key is encrypted RC4 and sent to server as encrypted_session_key
      compute_keys( sessionKey:session_key );
      session_key = encrypted_session_key;
    }
  }

  lm_resplen = strlen( lm );
  ntlm_resplen = strlen( nt );
  lmoff = 64;
  ntlmoff = lmoff + lm_resplen;

  lm_resp_hi = lm_resplen / 256;
  lm_resp_lo = lm_resplen % 256;

  ntlm_resp_hi = ntlm_resplen / 256;
  ntlm_resp_lo = ntlm_resplen % 256;

  lmoff_hi = lmoff / 256;
  lmoff_lo = lmoff % 256;

  ntlmoff_hi = ntlmoff / 256;
  ntlmoff_lo = ntlmoff % 256;

  lm_resp_length = raw_string( lm_resp_lo ) + raw_string( lm_resp_hi ); # length 2 bytes
  ntlm_resp_length = raw_string( ntlm_resp_lo ) + raw_string( ntlm_resp_hi ); # length 2 bytes
  lm_resp_offset = raw_string( lmoff_lo ) + raw_string( lmoff_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes
  ntlm_resp_offset = raw_string( ntlmoff_lo ) + raw_string( ntlmoff_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  workstname = "";
  user = login;

  username = insert_hexzeros( in:login );
  wsdomain = insert_hexzeros( in:domain );
  wsname = insert_hexzeros( in:workstname );

  wsdomlen = ( strlen( wsdomain ) );
  wsnmlen = ( strlen( wsname ) );
  usernmlen = ( strlen( username ) );
  wsdomainoff = ntlmoff + ntlm_resplen;
  usernameoff = wsdomainoff + wsdomlen;
  wsnameoff = usernameoff + usernmlen;

  wsdomain_hi = wsdomlen / 256;
  wsdomain_lo = wsdomlen % 256;

  wsname_hi = wsnmlen / 256;
  wsname_lo = wsnmlen % 256;

  username_hi = usernmlen / 256;
  username_lo = usernmlen % 256;

  wsdomoffset_hi = wsdomainoff / 256;
  wsdomoffset_lo = wsdomainoff % 256;

  wsnameoffset_hi = wsnameoff / 256;
  wsnameoffset_lo = wsnameoff % 256;

  usernameoffset_hi = usernameoff / 256;
  usernameoffset_lo = usernameoff % 256;

  wsdomainlen = raw_string( wsdomain_lo ) + raw_string( wsdomain_hi ); # length 2 bytes
  wsnamelen = raw_string( wsname_lo ) + raw_string( wsname_hi ); # length 2 bytes

  usernamelen = raw_string( username_lo ) + raw_string( username_hi ); # length 2 bytes
  usernameoffset = raw_string( usernameoffset_lo ) + raw_string( usernameoffset_hi ) + raw_string( 0x00, 0x00 );

  wsdomainoffset = raw_string( wsdomoffset_lo ) + raw_string( wsdomoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes
  wsnameoffset = raw_string( wsnameoffset_lo ) + raw_string( wsnameoffset_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  # encrypted session key
  sec_key_len = strlen( session_key );
  sec_key_off = wsnameoff + wsnmlen;

  seckey_hi = sec_key_len / 256;
  seckey_lo = sec_key_len % 256;
  seckeyoff_hi = sec_key_off / 256;
  seckeyoff_lo = sec_key_off % 256;

  seckeylength = raw_string( seckey_lo ) + raw_string( seckey_hi ); # length 2 bytes
  seckeyoffset = raw_string( seckeyoff_lo ) + raw_string( seckeyoff_hi ) + raw_string( 0x00, 0x00 ); # offset 4 bytes

  os = "Unix";
  native_os = insert_hexzeros( in:os );
  lanman = "OpenVAS";
  native_lanmanager = insert_hexzeros( in:lanman );

  #Creating NTLMSSP in Security Blob for the request

  # raw string contains NTLMSSP: sign, type1 msgtype, flags
  ntlmssp = raw_string( 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53,
                        0x50, 0x00, 0x03, 0x00, 0x00, 0x00 );

  # Lan Manager Response
  ntlmssp += lm_resp_length + lm_resp_length + lm_resp_offset ;

  # NTLM Response
  ntlmssp += ntlm_resp_length + ntlm_resp_length + ntlm_resp_offset;
  ntlmssp += wsdomainlen + wsdomainlen + wsdomainoffset + usernamelen + usernamelen + usernameoffset + wsnamelen + wsnamelen + wsnameoffset + seckeylength + seckeylength + seckeyoffset;

  # adding flags
  ntlmssp += raw_string( 0x15, 0x82, 0x08, 0x60 );

  #adding NT LM Challenge response
  ntlmssp += lm + nt ;

  # adding workstation domain
  if( wsdomain ) ntlmssp += toupper( wsdomain );

  #adding username
  ntlmssp += username;

  #adding workstation name
  ntlmssp += toupper( wsname );

  #adding session key
  ntlmssp += session_key;

  #NTLMSSP length
  ntlmssplen = 64 + lm_resplen + ntlm_resplen + wsdomlen + wsnmlen + usernmlen + sec_key_len;

  #Security Blob
  if( version == 2 ) {

    len = ntlmssplen + 12;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob = raw_string( 0xa1, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo );
    len = ntlmssplen + 8;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob += raw_string( 0x30, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo );
    len = ntlmssplen + 4;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob += raw_string( 0xa2, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo );
    len = ntlmssplen;
    len_hi = len / 256;
    len_lo = len % 256;
    secblob += raw_string( 0x04, 0x82 ) + raw_string( len_hi ) + raw_string( len_lo ) + ntlmssp;
    secbloblen = 16 + ntlmssplen;
  } else {
    secblob = ntlmssp;
    secbloblen = 12 + ntlmssplen;
  }

  secbloblen_hi = secbloblen / 256;
  secbloblen_lo = secbloblen % 256;
  bytecount = secbloblen + 1 + strlen( native_os ) + 2 + strlen( native_lanmanager ) + 2;
  bytecount_hi = bytecount / 256;
  bytecount_lo = bytecount % 256;

  #Session Setup Request
  st += raw_string( 0x19, 0x00 );
  st += raw_string( 0x00, 0x01, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00 );
  st += raw_string( secbloblen_lo ) + raw_string( secbloblen_hi ) +
        raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  st += secblob;

  #length of entire packet
  len = strlen( st );
  len_hi = len / 256;
  len_lo = len % 256;

  stt = raw_string( 0x00, 0x00, len_hi, len_lo ) + st;

  req = stt;

  send(socket:soc, data:req);
  r = smb_recv( socket:soc );
  if( strlen( r ) < 13 ) return FALSE;

  multiplex_id += 1;

  if( ord( r[12] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

#--------------------NTLMSSP IMPLEMENTATION END---------------------------------------------------#
#-------------------------------------------------------------------------------------------------#

# @brief Computes all necessary cryptographic keys.
# @param sessionKey The session key extracted from NTLM
# @return Nothing. Everything is written into global variables.
function compute_keys( sessionKey ) {
  local_var sessionKey, label;

  if( smbv3 ) {
    # Compute Signing Key
    label = raw_string( 0x53, 0x4D, 0x42, 0x32, 0x41, 0x45, 0x53, 0x43, 0x4D, 0x41, 0x43, 0x00 ); # SMB2AESCMAC
    ctx = raw_string( 0x53, 0x6D, 0x62, 0x53, 0x69, 0x67, 0x6E, 0x00 ); # SmbSign
    sign_key = smb3kdf( key: sessionKey, label:label, ctx:ctx, lvalue:128 );

    # Compute Encryption Key
    label = raw_string( 0x53, 0x4D, 0x42, 0x32, 0x41, 0x45, 0x53, 0x43, 0x43, 0x4D, 0x00 ); # SMB2AESCCM
    ctx = raw_string( 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x49, 0x6E, 0x20, 0x00 ); # ServerIn with whitespace at the end
    encryptKey = smb3kdf( key:sessionKey, label:label, ctx:ctx, lvalue:128 );

    # Compute Decryption Key
    label = raw_string( 0x53, 0x4D, 0x42, 0x32, 0x41, 0x45, 0x53, 0x43, 0x43, 0x4D, 0x00 ); # SMB2AESCCM
    ctx = raw_string( 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x4F, 0x75, 0x74, 0x00 ); # ServerOut with whitespace at the end
    decryptKey = smb3kdf( key:sessionKey, label:label, ctx:ctx, lvalue:128 );
  } else if ( smbv2 ) {
    sign_key = sessionKey;
  }

}

# @brief Extracts the server guid, capabilities, security mode and selected dialect from a negotiate protocol response.
#        These parameters are later used in the secure dialect negotiation.
# @param r The received negotiate protocol response.
# @return Returns NULL or FALSE in case the received response is too short or some values are not present.
#         Returns TRUE if the extraction of the parameters was successful.
function smb2_neg_extract_serv_params( r ) {

  local_var r;

  if ( isnull ( r ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb2_neg_extract_serv_params" );

  # SMB2 Header is too short. 4 Bytes from the Netbios Session Service and 64 Bytes from the SMB2 Header
  if( strlen( r ) < 68 ) return NULL;

  # We store the field values as a string because we do not need any integer operation later on
  serv_sec_mode = substr( r, 70, 71 );
  serv_dialect = substr( r, 72, 73 );
  server_guid = substr( r, 76, 91 );
  serv_capabilities = substr( r, 92, 95 );

  # We failed to extract one of the values because the received answer was too short
  if( serv_capabilities == "" || serv_dialect == "" || server_guid == "" || serv_capabilities == "" ) {
    return FALSE;
  }

  return TRUE;
}

# @brief Sends the request for the secure dialect negotiation and interprets the received answer.
# @note Technically this also could be used for SMBv2 connections but it has to be checked.
# @param uid The session id.
# @param tid The tree id.
# @param soc The socket used for the communication.
# @return Returns FALSE in case of a failure otherwise TRUE is returned.
function secure_dialect_negotiation( uid, tid, soc ) {

  # g_mhi, g_mlo are global variables

  local_var soc, req, uid, tid, len, len_hi, len_lo, sig, r, status, status2, seq_number, r_head, server_resp, orig_sign, serv_sign, data;

  # This request needs to be signed when send unencrypted.
  # We should not send the request when signing is disabled.
  # We are returning TRUE than so that scripts that would abort in case of a failure are not affected.
  # The request should however be send if encryption is enabled.
  if( ( smbv3 && isSignActive ) || ( smbv3 && smbEncryption ) || ( smbv2 && isSignActive ) ) {
    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;

    #SMB2 header [MS-SMB2 2.2.1.2]
    req = raw_string( 0xfe, 0x53, 0x4d, 0x42 ); # Protocol ID
    req += raw_string( 0x40, 0x00 ); # Structure Size
    req += raw_string( 0x01, 0x00 ); # Credit Charge
    req += raw_string( 0x00, 0x00, 0x00, 0x00 ); # ChannelSequence, Reserved, Status
    req += raw_string( 0x0b, 0x00 ); # Command --> IOCTL
    req += raw_string( 0x00, 0x00 ); # Credit request

    if( isSignActive ) {
      req += raw_string( 0x08, 0x00, 0x00, 0x00 ); # Flags
    } else {
      req += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Flags
    }

    req += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Next Command
    req += raw_string( g_mlo, g_mhi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Message ID
    req += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Reserved
    req += tid; # TreeID
    req += uid; # SessionID
    req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ); # Signature

    # IOCTL Request [MS-SMB2 2.2.31]
    req += raw_string( 0x39, 0x00 ); # Structure Size
    req += raw_string( 0x00, 0x00 ); # Reserved
    req += raw_string( 0x04, 0x02, 0x14, 0x00 ); # Command --> FSCTL_VALIDATE_NEGOTIATE_INFO
    req += raw_string( 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ); # File ID --> [MS-SMB2 3.3.5.15] for explanation
    req += raw_string( 0x78, 0x00, 0x00, 0x00 ); # Input Offset

    if( defined_func( 'smb3kdf' ) ) {
      req += raw_string( 0x20, 0x00, 0x00, 0x00 ); # Input Count
    } else {
      req += raw_string( 0x1C, 0x00, 0x00, 0x00 ); # Input Count
    }

    req += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Max Input Response
    req += raw_string( 0x78, 0x00, 0x00, 0x00 ); # Output Offset
    req += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Output Count

    if( defined_func( 'smb3kdf' ) ) {
      req += raw_string( 0x20, 0x00, 0x00, 0x00 ); # Max Output Response
    } else {
      req += raw_string( 0x1C, 0x00, 0x00, 0x00 ); # Max Output Response
    }

    req += raw_string( 0x01, 0x00, 0x00, 0x00 ); # Flags
    req += raw_string( 0x00, 0x00, 0x00, 0x00 ); # Reserved2

    # VALIDATE_NEGOTIATE_INFO Request [MS-SMB2 2.2.31.4]
    req += raw_string( 0x40, 0x00, 0x00, 0x00 ); # Capabilities
    req += client_guid; # Client GUID
    req += raw_string( 0x01, 0x00 ); # Security Mode

    if( defined_func( 'smb3kdf' ) ) {
      req += raw_string( 0x04, 0x00 ); # Dialect Count
      req += raw_string( 0x02, 0x02 ); # SMB 2.0.2
      req += raw_string( 0x10, 0x02 ); # SMB 2.1
      req += raw_string( 0x00, 0x03 ); # SMB 3.0
      req += raw_string( 0x02, 0x03 ); # SMB 3.0.2
    } else {
      req += raw_string( 0x02, 0x00 ); # Dialect Count
      req += raw_string( 0x02, 0x02 ); # SMB 2.0.2
      req += raw_string( 0x10, 0x02 ); # SMB 2.1
    }

    #length of entire packet
    len = strlen( req );
    len_hi = len / 256;
    len_lo = len % 256;

    if( isSignActive ) {

      if( smbv3 ) {
        sig = smb_cmac_aes_signature( buf:req, key:sign_key );
      } else if ( smbv2 ) {
        sig = get_smb2_signature( buf:req, key:sign_key );
      }

      if( isnull( sig ) ) {
        set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#secure_dialect_negotiation: buf or key passed to signature function empty / too short" );
        return FALSE;
      }

      data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
    } else {
      data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req ;
    }

    if( smbEncryption ) {
      data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
    }

    # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
    send( socket:soc, data:data );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return FALSE;

    ##If status is pending, wait for response
    status = ord( r[12] );
    status2 = ord( r[13] );

    while( status == 3 && status2 == 1 ) {

      ##PDU will arrive late
      r = smb_recv( socket:soc );
      if( strlen( r ) < 14 ) return FALSE;

      status = ord( r[12] );
      status2 = ord( r[13] );
    }

    multiplex_id += 1;
    if( isSignActive ) {
      # verify signature
      seq_number += 1;
      len = strlen( r );

      r_head = substr( r, 0, 3 );
      r = substr( r, 4, strlen( r ) - 1 );

      if( smbv3 ) {
        server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
      } else if( smbv2 ) {
        server_resp = get_smb2_signature( buf:r, key:sign_key );
      }
      if( isnull( server_resp ) ) return FALSE;

      if( ( strlen( server_resp ) < 64 ) || ( strlen( r ) < 64 ) ) {
        return FALSE;
      }

      orig_sign = substr( r, 48, 63 );
      serv_sign = substr( server_resp, 48, 63 );

      if( orig_sign != serv_sign ) {
        return FALSE;
      } else {
        r = r_head + r;
      }
      # -> END TODO
    }

    status = substr( r, 12, 15 );
    # Signing was successful but the server does not support the FCTL
    # Still should be counted as successful
    if( hexstr(status) == "bb0000c0" || hexstr(status) == "100000c0" || hexstr(status) == "280100c0" ) {
      return r;
    }

    # Comparing the saved parameters from the protocol negotiation response against the parameters returned in the secure dialect negotiation.
    if( serv_capabilities != substr( r, 116, 119 ) ) {
      return FALSE;
    }

    if( server_guid != substr( r, 120, 135 ) ) {
      return FALSE;
    }

    if( serv_sec_mode != substr( r, 136, 137 ) ) {
      return FALSE;
    }

    if( serv_dialect != substr( r, 138, 139 ) ) {
      return FALSE;
    }

    if( ord( r[12] ) == 0 ) {
      return r;
    } else {
      return FALSE;
    }

  } else {
      return TRUE;
  }
}

# @brief Creates the complete smb2_transform header package
# @note Once we introduce more encryption algorithms with SMBv3.1.1 we need to change the nonce part
# @param len_hi The original high bytes of the message size
# @param len_lo The original low bytes of the message size
# @param sig The original request
# @param uid The session id.
# @return Encrypted original data with the smb2_transform_header added.
function create_smb2_transform_header_package( len_hi, len_lo, req, uid ) {
  local_var protId, nonce, nonce2, aad, data, uid, len, len_hi, len_lo, req, ret, tag, crypt, encrypt, signature;

  #[MS-SMB2 2.2.41]
  protId = raw_string( 0xfd, 0x53, 0x4d, 0x42 );

  # This is an implementation specific value. It should be unique for every encrypted message in one session.
  # We need 11 Bytes of random data
  nonce = bn_random( need:8*11 );
  # Weird bug where nonce is sometimes only 10 bytes long
  while( strlen( nonce ) < 11 ) {
    nonce = bn_random( need:8*11 );
  }

  nonce2 = raw_string( 0x00, 0x00, 0x00, 0x00, 0x00 ); # Reserved part of nonce

  aad = nonce + nonce2 + raw_string( len_lo, len_hi, 0x00, 0x00 ); # OrigmessageSize
  aad += raw_string( 0x00, 0x00 ); # Reserved
  aad += raw_string( 0x01, 0x00 ); # Flag
  aad += uid; # SessionID

  # The SMB2_TRANSFORM_HEADER starting with Nonce is AAD that needs to be supplied to the encrypt function
  # The returned MAC is the signature of the TRANSFORM HEADER.

  crypt = aes128_ccm_encrypt_auth( key:encryptKey, iv:nonce, data:req, aad:aad );
  encrypt = crypt[0];
  signature = crypt[1];

  data = protId + signature + aad + encrypt;

  len = strlen( data );
  len_hi = len / 256;
  len_lo = len % 256;

  data = raw_string( 0x00, 0x00, len_hi, len_lo ) + data ;
  return data;
}

# @brief Creates the Session Setup Request with the SMB header for older NTLM versions.
# @param soc The socket used for the connection.
# @param login The username used for the login.
# @param password The password used for the login.
# @param domain The Netbios domain name.
# @param cs The selected dialect.
# @param version The NTLM version that should be used.
# @return Return the received answer or FALSE in case somethin fails.
function smb_session_setup_NTLMvN( soc, login, password, domain, cs, version ) {

  local_var soc, login, password, domain, cs, version;
  local_var oid, NT_H, LM_H, lm, nt, ntlmv2_hash;
  local_var native_os, native_lanmanager, extra, len, bcc;
  local_var len_hi, len_low, bcc_hi, bcc_lo;
  local_var plen_lm, plen_nt, plen, st, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_session_setup_NTLMvN" );
  if( isnull( login ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#smb_session_setup_NTLMvN" );
  if( isnull( password ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#password#-#smb_session_setup_NTLMvN" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb_session_setup_NTLMvN" );

  if( isnull( cs ) ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.102011" ) # smb_neg_prot_cs in smb_nativelanman.nasl doesn't return a value against Samba servers
      set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#cs#-#smb_session_setup_NTLMvN" );
  }


  if( isnull( version ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#smb_session_setup_NTLMvN" );

  if( version == 1 ) {
    if( password ) {
      NT_H = nt_owf_gen( password );
      if( isnull( NT_H ) ) return FALSE;

      LM_H = lm_owf_gen( password );
      if( isnull( LM_H ) ) return FALSE;

      lm = NTLMv1_HASH( cryptkey:cs, passhash:LM_H );
      if( isnull( lm ) ) return FALSE;

      nt = NTLMv1_HASH( cryptkey:cs, passhash:NT_H );
      if( isnull( nt ) ) return FALSE;

    }
  } else {
    if( password ) {
      NT_H = nt_owf_gen( password );
      if( isnull( NT_H ) ) return FALSE;

      ntlmv2_hash = ntv2_owf_gen( owf:NT_H, login:login, domain:domain );
      if( isnull( ntlmv2_hash ) ) return FALSE;

      lm = NTLMv2_HASH( cryptkey:cs, passhash:ntlmv2_hash, length:8 );
      if( isnull( lm ) ) return FALSE;

      nt = NTLMv2_HASH( cryptkey:cs, passhash:ntlmv2_hash, length:64 );
      if( isnull( nt ) ) return FALSE;
    }
  }

  extra = 0;
  native_os = "Unix";
  native_lanmanager = "OpenVAS";
  if( ! domain ) domain = "WORKGROUP";

  if( domain ) {
    extra = 3 + strlen( domain ) + strlen( native_os ) + strlen( native_lanmanager );
  } else {
    extra = strlen( native_os ) + strlen( native_lanmanager ) + 2;
  }

  len = strlen( login ) + strlen( lm ) + strlen( nt ) + 62 + extra;
  bcc = 1 + strlen( login ) + strlen( lm ) + strlen( nt ) + extra;

  len_hi = len / 256;
  len_low = len % 256;

  bcc_hi = bcc / 256;
  bcc_lo = bcc % 256;

  if( password ) {
    plen_lm = strlen( lm );
    plen_nt = strlen( nt );
  } else {
    plen_lm = 0;
    plen_nt = 0;
    plen = 0;
  }

  pass_len_hi = pass_len / 256;
  pass_len_lo = pass_len % 256;

  if( ! login )    login="";
  if( ! password ) password="";

  st = raw_string( 0x00,0x00,
                   len_hi, len_low, 0xFF, 0x53,
                   0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x08,
                   0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x28, 0x00, 0x00, g_mlo, g_mhi, 0x0D, 0xFF,
                   0x00, 0x00, 0x00, 0x00, 0x44, 0x02, 0x00, 0xA0,
                   0xF5, 0x00, 0x00, 0x00, 0x00, plen_lm, 0x00, plen_nt,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, bcc_lo, bcc_hi ) + lm + nt + toupper( login ) +
                   raw_string( 0 );

  if( domain ) st += domain + raw_string( 0x00 );

  st += native_os + raw_string( 0x00 ) + native_lanmanager + raw_string( 0x00 );

  send( socket:soc, data:st );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 10 ) return FALSE;

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Establishes the session after the protocol negotiation for the SMB header.
# @param soc The socket used for the connection.
# @param login The username used for the login.
# @param password The password used for the login.
# @param domain The nebtios domain name.
# @param prot The answer from the negotiation process.
# @return Returns NULL or FALSE in case the process fails.
#         When the process was successful the last answer of the Session Setup Process is returned.
function smb_session_setup( soc, login, password, domain, prot ) {

  # ct_flag, ntlmv2_flag and ntlmssp_flag are global_vars!!!

  local_var soc, login, password, domain, prot;
  local_var prot2, r, ret, cs, flags, flg_str, uid, addr_list, smbVersion;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_session_setup" );
  if( isnull( login ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#smb_session_setup" );
  if( isnull( password ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#password#-#smb_session_setup" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb_session_setup" );
  if( isnull( prot ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb_session_setup" );

  if( smb_neg_prot_value( prot:prot ) < 7 ) {
    if( ct_flag == "yes" ) {
      return NULL;
    } else {
      return smb_session_setup_cleartext( soc:soc, login:login, password:password, domain:domain );
    }
    ntlmssp_flag = 0;
  } else {
    if( ntlmssp_flag ) {
      # Check For SMB2
      if( strlen( prot ) < 5 ) {
        return NULL;
      }
      if( ord( prot[4] ) == 254 ) {
        # Needs to be negotiated again with the correct header so all information are negotiated correctly
        prot2 = smb2_neg_prot( soc:soc );
        if( ! prot2 ) {
          close( soc );
          return NULL;
        }

        ret = smb2_neg_extract_serv_params( r:prot2 );

        # We want to abort the communication if the parameter extraction failed
        if( isnull(ret) || !ret ) {
          return NULL;
        }

        smbVersion = smb_neg_prot_value( prot:prot2 );

        # SMBv3.0 and SMBv3.0.2 only support cmac signing
        # We need to know the version to decide between SMBv2 or SMBv3 signing
        if( smbVersion == 770 || smbVersion == 768 ) {
          smbv3 = TRUE;
        } else {
          smbv2 = TRUE;
        }

        r = smb2_session_setup( soc:soc, login:login, password:password, domain:domain, prot:prot2 );

        # Decides if encryption has been negotiated.
        # Field is only valid if it belongs to the SMB3.x family
        # [MS-SMB2 2.2.6]
        if( smbv3 ) {
          smbEncryption = smb2_neg_prot_encrypt( prot:r );
          # [MS-SMB2 3.2.5.3.1]
          # If we have encryption enabled we do not sign the package that is going to be encrypted
          if( smbEncryption ) {
            isSignActive = FALSE;
          }
        }

        return r;
      } else {
        # SMB NTLM stuff. Naming is similar to SMB2 but functions have different work to do
        #Step 1: Negotiation
        ret = smb_session_setup_NTLMSSP_NEGOT( soc:soc, domain:domain );
        if( ! ret ) return FALSE;

        #Step 2:  Read the server challenge from response ret
        cs = smb_session_setup_NTLMSSP_extract_chal( ret:ret );

        #Step 3: Authentication
        flags = smb_session_setup_NTLMSSP_extract_flag( ret:ret );
        flg_str = smb_session_setup_NTLMSSP_auth_flags( neg_flags:flags );
        uid = session_extract_uid( reply:ret );
        if( ! uid ) return FALSE;

        addr_list = smb_session_setup_NTLMSSP_extract_addrlist( ret:ret );
        # call the function to get address list from type 2 message
        if( ntlmv2_flag ) {
          ret = smb_session_setup_NTLMSSP_AUTH( soc:soc, login:login, password:password, domain:domain, version:2, cs:cs,
                                                uid:uid, server_flags:flags, flag_str:flg_str, addr_list:addr_list );
        } else {
          ret = smb_session_setup_NTLMSSP_AUTH( soc:soc, login:login, password:password, domain:domain, version:2, cs:cs,
                                                uid:uid, server_flags:flags, flag_str:flg_str, addr_list:addr_list );
          if( ! ret ) {
            ret = smb_session_setup_NTLMSSP_AUTH( soc:soc, login:login, password:password, domain:domain, version:1, cs:cs,
                                                  uid:uid, server_flags:flags, flag_str:flg_str, addr_list:addr_list );
          }
        }
        return ret;
      }
    } else {
      cs = smb_neg_prot_cs( prot:prot );
      ret = smb_session_setup_NTLMvN( soc:soc, login:login, password:password, domain:domain, cs:cs, version:2 );
      if( ! ret && ! ntlmv2_flag ) {
        ret = smb_session_setup_NTLMvN( soc:soc, login:login, password:password, domain:domain, cs:cs, version:1 );
      }
      return ret;
    }
  }
}

# @brief Establishes the session after the protocol negotiation has finished. The SMBv2 header is used.
# @note SMB2 session setup <-- Previous comment
# @param soc The socket used for the connection.
# @param login The username used for the login.
# @param password The password used for the login.
# @param domain The netbios domain name.
# @param prot The received answer from the protocol negotiation process.
# @return Returns FALSE if the process fails otherwise the answer of the session setup process is returned.
function smb2_session_setup( soc, login, password, domain, prot ) {

  # ntlmv2_flag and ntlmssp_flag are global_vars!!!

  local_var soc, login, password, domain, prot;
  local_var ret, cs, flags, flg_str, ssid, addr_list;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2_session_setup" );
  if( isnull( login ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#smb2_session_setup" );
  if( isnull( password ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#password#-#smb2_session_setup" );
  if( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#smb2_session_setup" );
  if( isnull( prot ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prot#-#smb2_session_setup" );

  if( ntlmssp_flag ) {

    #Step 1: Negotiation
    ret = smb2_session_setup_NTLMSSP_NEGOT( soc:soc, domain:domain );
    if( ! ret ) return FALSE;

    #Step 2: Read the server challenge from response ret
    cs = smb_session_setup_NTLMSSP_extract_chal( ret:ret );

    #Step 3: Authentication
    flags = smb_session_setup_NTLMSSP_extract_flag( ret:ret );
    flg_str = smb_session_setup_NTLMSSP_auth_flags( neg_flags:flags );
    ssid = session_extract_sessionid( reply:ret );
    if( ! ssid ) return FALSE;

    addr_list = smb_session_setup_NTLMSSP_extract_addrlist( ret:ret );

    # call the function to get address list from type 2 message
    if( ntlmv2_flag ) {
      ret = smb2_session_setup_NTLMSSP_AUTH( soc:soc, login:login, password:password,
                                             domain:domain, version:2, cs:cs, ssid:ssid, server_flags:flags, flag_str:flg_str, addr_list:addr_list );
    } else {
       ret = smb2_session_setup_NTLMSSP_AUTH( soc:soc, login:login, password:password,
                                              domain:domain, version:2, cs:cs, ssid:ssid, server_flags:flags, flag_str:flg_str, addr_list:addr_list );

       if( ! ret ) {
         ret = smb2_session_setup_NTLMSSP_AUTH( soc:soc, login:login, password:password,
                                                domain:domain, version:1, cs:cs, ssid:ssid, server_flags:flags, flag_str:flg_str, addr_list:addr_list );
       }
    }
    return ret;
  } else {
    cs = smb_neg_prot_cs( prot:prot );
    ret = smb_session_setup_NTLMvN( soc:soc, login:login, password:password, domain:domain, cs:cs, version:2 );
    if( ! ret && ! ntlmv2_flag ) {
      ret = smb_session_setup_NTLMvN( soc:soc, login:login, password:password, domain:domain, cs:cs, version:1 );
    }
    return ret;
  }
}


# @brief Establish a tree connect request to a remote share while using the SMB header together with NTLMSSP.
# @note connection to the remote IPC share <-- Previous comment
# @param soc The socket used for the connection
# @param name The netbios name of a host.
# @param uid The sessionid of the SMB session.
# @param share The name of the share
# @return Returns FALSE in case of something fails. If everything is fine the answer to this request is returned.
function smb_tconx_NTLMSSP( soc, name, uid, share ) {

  # s_sign_key, sign_key, isSignActive, g_mhi, g_mlo, seq_number and multiplex_id are global_vars!!!

  local_var soc, name, uid, share;
  local_var high, low, n, nm, sh, ulen, len, passlen, pwd;
  local_var len_hi, len_lo, ulen_hi, ulen_lo, passlen_hi, passlen_lo;
  local_var req, r, server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_tconx_NTLMSSP" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smb_tconx_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb_tconx_NTLMSSP" );
  if( isnull( share ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#smb_tconx_NTLMSSP" );

  high = uid / 256;
  low = uid % 256;
  n = chomp( name );
  nm = insert_hexzeros( in:n );
  sh = insert_hexzeros( in:share );

  ulen = 8 + strlen( nm ) + strlen( sh ) + 6;
  len = 43 + ulen;
  #Assuming case: NEGOTIATE_SECURITY_USER_LEVEL enabled
  passlen = 1;
  pwd = "";

  #TODO: cases SECURITY_CHALLENGE_RESPONSE or otherwise

  len += passlen;
  ulen += passlen;
  len_hi = len / 256;
  len_lo = len % 256;
  ulen_hi = ulen / 256;
  ulen_lo = ulen % 256;
  passlen_hi = passlen / 256;
  passlen_lo = passlen % 256;
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0x00, 0x00 ) + raw_string( len_hi ) + raw_string( len_lo ) +
        raw_string( 0xFF, 0x53, 0x4D, 0x42, 0x75, 0x00,
                    0x00, 0x00, 0x00, 0x08 );

  if( isSignActive ) {
    req += raw_string( 0x05, 0xc8 );
  } else {
    req += raw_string( 0x01, 0xc8 );
  }

  req += raw_string( 0x00, 0x00 );
  #putting signature null initially
  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
  req += raw_string( 0x00, 0x00, 0xff, 0xff, 0x33, 0x0c, low, high,
                     g_mlo, g_mhi, 0x04, 0xFF, 0x00, 0x00, 0x00, 0x08,
                     0x00, passlen_lo, passlen_hi, ulen_lo, ulen_hi ); #43

  if( passlen == 1 ) {
    req += raw_string( 0x00 );
  } else {
    req += pwd;
  }

  req += raw_string( 0x5C, 0x00, 0x5C, 0x00 ) + nm + raw_string( 0x5C, 0x00 ) + sh + raw_string( 0x00, 0x00 ) + "?????" + raw_string( 0x00 );

  if( isSignActive ) {
    len += 4;
    seq_number += 1;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number ); # TBD: This overwrites the previous declared req...
    if( isnull( req ) ) return FALSE;
  }

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 10 ) return FALSE;

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( ord(r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Establishes a tree connect to a remote share using the SMBv2 header together with NTLMSSP.
# @note NTLMSSP <-- Previous comment
# @param soc The socket used for the connection
# @param name The netbios name of a host.
# @param uid The sessionid of the SMB session.
# @param share The name of the share
# @return Returns FALSE in case of something fails. If everything is fine the answer to this request is returned.
function smb2_tconx_NTLMSSP( soc, name, uid, share ) {

  # sign_key, isSignActive, g_mhi, g_mlo, seq_number and multiplex_id are global_vars!!!

  local_var soc, name, uid, share;
  local_var n, nm, sh, ulen, len, passlen, pwd;
  local_var len_hi, len_lo, ulen_hi, ulen_lo, passlen_hi, passlen_lo;
  local_var req, tree, treelen, treelen_hi, treelen_lo, data;
  local_var r, status, status2, r_head, server_resp, orig_sign, serv_sign, iv;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2_tconx_NTLMSSP" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smb2_tconx_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb2_tconx_NTLMSSP" );
  if( isnull( share ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#smb2_tconx_NTLMSSP" );

  n = chomp( name );
  nm = insert_hexzeros( in:n );
  sh = insert_hexzeros( in:share );

  ulen = 8 + strlen( nm ) + strlen( sh ) + 6;
  len = 43 + ulen;
  #Assuming case: NEGOTIATE_SECURITY_USER_LEVEL enabled
  passlen = 1;
  pwd = "";

  #TODO: cases SECURITY_CHALLENGE_RESPONSE or otherwise

  len += passlen;
  ulen += passlen;
  len_hi = len / 256;
  len_lo = len % 256;
  ulen_hi = ulen / 256;
  ulen_lo = ulen % 256;
  passlen_hi = passlen / 256;
  passlen_lo = passlen % 256;
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x81, 0x1f );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string(0x00, 0x00, 0x00, 0x00);
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00 );

  req += uid + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  tree = raw_string( 0x5c, 0x00, 0x5c, 0x00 ) + nm + raw_string( 0x5C, 0x00 ) + sh;
  treelen = strlen( tree );
  treelen_hi = treelen / 256;
  treelen_lo = treelen % 256;

  req += raw_string( 0x09, 0x00, 0x00, 0x00, 0x48, 0x00, treelen_lo, treelen_hi ) + tree ;

  #length of entire packet
  len = strlen( req );
  len_hi = len / 256;
  len_lo = len % 256;

  if( isSignActive ) {

    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }

    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#smb2_tconx_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }

    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return FALSE;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );

  while( status == 3 && status2 == 1 ) {

    ##PDU will arrive late
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return FALSE;

    status = ord( r[12] );
    status2 = ord( r[13] );
  }
  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen(r);

    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );

    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;

    if( ( strlen( server_resp ) < 64 ) || ( strlen( r ) < 64 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 48, 63 );
    serv_sign = substr(server_resp, 48, 63);

    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }
    # END TODO ->

  }
  if( ord( r[12] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Establishes a tree connect request with an SMB header. A bit unclear what the real purpose is.
# @note It is only used in secpod_ms09-001_remote.nasl it seems to test for a specific SMB vulnerability.
# @param soc The socket used for the connection
# @param name The netbios name of a host.
# @param uid The sessionid of the SMB session.
# @param share The name of the share
# @return In case of a failure return is FALSE. If everything works fine the answer is returned.
function smb_tconx_cleartext( soc, name, uid, share ) {

  local_var soc, name, uid, share;
  local_var high, low, len, ulen, req, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_tconx_cleartext" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smb_tconx_cleartext" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb_tconx_cleartext" );
  if( isnull( share ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#smb_tconx_cleartext" );

  high = uid / 256;
  low = uid % 256;
  len = 48 + strlen( name ) + strlen( share ) + 6;
  ulen = 5 + strlen( name ) + strlen( share ) + 6;

  req = raw_string( 0x00, 0x00, 0x00, len, 0xFF, 0x53, 0x4D,
                    0x42, 0x75, 0x00, 0x00, 0x00, 0x00, 0x08,
                    0xc8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x28, low, high, 0x00,
                    0x00, 0x04, 0xFF, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01, 0x00, ulen, 0x00, 0x00, 0x5C,
                    0x5C ) + name + raw_string( 0x5C ) + share +
                    raw_string( 0x00 ) + "?????"  + raw_string( 0x00 );

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );

  if( strlen( r ) < 10 ) return FALSE;

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Establishes a tree connect using NTLMSSP with SMB when set otherwise same as @ref smb_tconx_cleartext.
# @param soc The socket used for the connection
# @param name The netbios name of a host.
# @param uid The sessionid of the SMB session.
# @param share The name of the share
# @return In case of a failure return is FALSE. If everything works fine the answer is returned.
function smb_tconx( soc, name, uid, share ) {

  # ntlmssp_flag is global_var!!!!

  local_var soc, name, uid, share;
  local_var response, high, low, len, ulen, req, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_tconx" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smb_tconx" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb_tconx" );
  if( isnull( share ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#share#-#smb_tconx" );

  if( strlen( uid ) == 8 ) {
    response = smb2_tconx( soc:soc, name:name, share:share, uid:uid );
    return response;
  } else {
    if( ntlmssp_flag ) {
      response = smb_tconx_NTLMSSP( soc:soc, name:name, uid:uid, share:share );
      return response;
    } else {
      high = uid / 256;
      low = uid % 256;
      len = 48 + strlen( name ) + strlen( share ) + 6;
      ulen = 5 + strlen( name ) + strlen( share ) + 6;

      req = raw_string( 0x00, 0x00, 0x00, len, 0xFF, 0x53, 0x4D, 0x42, 0x75, 0x00,
                        0x00, 0x00, 0x00, 0x08, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x28, low, high, 0x00, 0x00, 0x04, 0xFF, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01, 0x00, ulen, 0x00, 0x00, 0x5C, 0x5C ) + name +
                        raw_string( 0x5C ) + share +raw_string( 0x00 ) + "?????"  +
                        raw_string( 0x00 );
      send( socket:soc, data:req );
      r = smb_recv( socket:soc );
      if( strlen( r ) < 10 ) return FALSE ;

      if( ord( r[9] ) == 0 ) {
        return r;
      } else {
        return FALSE;
      }
    }
  }
}

# @brief Establishes a tree connect using NTLMSSP with SMB2 when set otherwise same as @ref smb_tconx_cleartext.
# @param soc The socket used for the connection
# @param name The netbios name of a host.
# @param uid The sessionid of the SMB session.
# @param share The name of the share
# @return In case of a failure return is FALSE. If everything works fine the answer is returned.
function smb2_tconx( soc, name, share, uid ) {

  # ntlmssp_flag is global_var!!!!

  local_var soc, name, uid, share;
  local_var response, high, low, len, ulen, req, r;

  if( ntlmssp_flag ) {
    response = smb2_tconx_NTLMSSP( soc:soc, name:name, share:share, uid:uid );
    return response;
  } else {
    high = uid / 256;
    low = uid % 256;
    len = 48 + strlen( name ) + strlen( share ) + 6;
    ulen = 5 + strlen( name ) + strlen( share ) + 6;

    req = raw_string( 0x00, 0x00, 0x00, len, 0xFF, 0x53, 0x4D, 0x42, 0x75, 0x00,
                      0x00, 0x00, 0x00, 0x08, 0xc8, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x28, low, high,
                      0x00, 0x00, 0x04, 0xFF, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x01, 0x00, ulen, 0x00, 0x00, 0x5C, 0x5C ) + name +
                      raw_string( 0x5C ) + share + raw_string( 0x00 ) + "?????"  +
                      raw_string( 0x00 );
    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 10 ) return FALSE;

    if( ord( r[9] ) == 0 ) {
      return r;
    } else {
      return FALSE;
    }
  }
}


# @brief Extracting the id of the tree connect. Decides between SMBv1 and SMBv2 header.
# @note Extract the TID from the result of smb_tconx() <-- Previous comment
# @param reply The tree connect reply.
# @return Returns the tree connect id if successful otherwise returns FALSE.
function tconx_extract_tid( reply ) {

  local_var reply, ret, low, high;

  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#tconx_extract_tid" );

  if( strlen( reply ) < 30 ) return FALSE;

  # Check for the SMB2 header
  if( ord( reply[4] ) == 254 ) {
    ret = smb2_tconx_extract_tid( reply:reply );
    return ret;
  } else {
    low = ord( reply[28] );
    high = ord( reply[29] );
    ret = high * 256;
    ret = ret + low;
    return ret;
  }
}

# @brief Extracting the id of the tree connect when SMBv2 header is used.
# @note Extract the TID from the result of smb2_tconx() <-- Previous comment
# @param reply The tree connect reply.
# @return Returns the tree connect id if successful otherwise returns FALSE.
function smb2_tconx_extract_tid( reply ) {

  local_var reply, start, tid;

  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#smb2_tconx_extract_tid" );

  if( strlen( reply ) < 44 ) return FALSE;

  start = stridx( reply, "SMB" ); # TBD: What's the purpose of this? This will be replaced one line below again...
  # If we use start += for the next thing the first 4 can be deleted
  start = 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 8 + 4;
  # Netbios + protocolid + header length + credit charge + Status code (here with 2+2 while 4 should be used) + command + credits granted +
  # flags + chain offset + message id + process id
  #NTLMSSP tid is 4 bytes in size
  tid = (substr( reply, start, start + 3 ) );
  return tid;
}

# @brief Creates or opens a file with the SMBv1 header.
# @note Request the creation of a pipe to name. Name must contain '\'. for NTLMSSP <-- Previous comment
# @param soc The socket used for the connection.
# @param uid The sessionid.
# @param tid The id of the tree.
# @param name The name of the file.
# @param always_return_blob Value if the received answer should always be returned without signature verification.
# @return Returns FALSE if something fails otherwise the received answer is returned.
function smbntcreatex_NTLMSSP( soc, uid, tid, name, always_return_blob ) {

  # s_sign_key, sign_key, isSignActive, g_mhi, g_mlo, seq_number and multiplex_id are global_vars!!!

  local_var soc, uid, tid, name, always_return_blob;
  local_var tid_high, tid_low, uid_high, uid_low;
  local_var req, namelen, name_hi, name_lo, len, r;
  local_var server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smbntcreatex_NTLMSSP" );
  if( isnull( uid) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smbntcreatex_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smbntcreatex_NTLMSSP" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smbntcreatex_NTLMSSP" );

  tid_high = tid / 256;
  tid_low  = tid % 256;

  uid_high = uid / 256;
  uid_low  = uid % 256;

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  # 0xA2 SMB_COM_NT_CREATE_ANDX Create or open a file or a directory
  req = raw_string( 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00, 0x00, 0x00,
                    0x00, 0x18 );

  if( isSignActive ) {
    req += raw_string( 0x07, 0x00 );
  } else {
    req += raw_string( 0x03, 0x00 );
  }

  req += raw_string( 0x50, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x33, 0x0c );

  namelen = strlen( name );
  name_hi = namelen / 256;
  name_lo = namelen % 256;

  # 0x18 is the start of the CREATE_ANDX request
  req += raw_string( uid_low, uid_high, g_mlo, g_mhi, 0x18, 0xFF, 0x00, 0x00,
                     0x00, 0x00, name_lo, name_hi, 0x06, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x9F, 0x01, 0x02, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x02, 0x00, 0x00, 0x00, 0x00, ( strlen( name ) + 1 ) % 256, 0x00 ) + name +
                     raw_string( 0x00 );
  req = raw_string( 0x00, 0x00, 0x00, ( strlen( req ) % 256 ) ) + req;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number ); # TBD: This overwrites the previous declared req...
    if( isnull( req ) ) return FALSE;
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( always_return_blob ) {
    return r;
  }

  if( strlen( r ) < 10 ) return FALSE;

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( ord( r[9] ) == 0x00 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Creates or opens a file with the SMBv2 header.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param name The name of the file
# @param always_return_blob Value if the received answer should always be returned without signature verification.
# @return Returns FALSE or NULL in case of a failure, when successful the received answer is returned.
function smb2ntcreatex_NTLMSSP( soc, uid, tid, name, always_return_blob ) {

  # sign_key, isSignActive, g_mhi, g_mlo, seq_number and multiplex_id are global_vars!!!

  local_var soc, uid, tid, name, always_return_blob;
  local_var name_le, name, uc, req, namelen, name_hi, name_lo;
  local_var r, status, status2, r_head, orig_sign, server_resp, serv_sign, data;
  local_var len, len_hi, len_lo;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2ntcreatex_NTLMSSP" );
  if( isnull( uid) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb2ntcreatex_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb2ntcreatex_NTLMSSP" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smb2ntcreatex_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;
  name_le = strlen( name );
  name = substr( name, 1, name_le - 1 );
  uc = unicode( data:name );

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x60, 0x1f );
  # 0x05 0x00 is SMB2_CREATE command

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid );

  ##Signature
  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  namelen = strlen( name ) + 1;
  name_hi = namelen / 256;
  name_lo = namelen % 256;

  # Start of the SMB2_CREATE Request
  req += raw_string( 0x39, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x9f, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                     0x40, 0x00, 0x40, 0x00, 0x78, 0x00, 0x0c, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) + uc;

  #length of entire packet
  len = strlen( req );
  len_hi = len / 256;
  len_lo = len % 256;

  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#smb2ntcreatex_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return NULL;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {

    ##PDU will arrive late
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return NULL;

    status = ord( r[12] );
          status2 = ord( r[13] );
  }

  if( always_return_blob ) {
    return r;
  }

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;

    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr( r, 48, 63 );
    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );

    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }

  }
  # END TODO ->

  if( ord( r[12] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Uses @ref smb2ntcreatex_NTLMSSP if ntlmssp is set or else a simplified SMBv1 version without signature verification
#        is used to create or open a file.
# @note Request the creation of a pipe to name. Name must contain '\'. <-- Previous comment
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param name The name of the file.
# @param always_return_blob Value that decides if the signature verification should be skipped and the answer is returned immediately.
# @return Returns FALSE or NULL in case of a failure otherwise
function smb2ntcreatex( soc, uid, tid, name, always_return_blob ) {

  # ntlmssp_flag, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, name, always_return_blob;
  local_var response, tid_high, tid_low, uid_high, uid_low, req, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2ntcreatex" );
  if( isnull( uid) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb2ntcreatex" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb2ntcreatex" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smb2ntcreatex" );

  if( ntlmssp_flag ) {
    response = smb2ntcreatex_NTLMSSP( soc:soc, uid:uid, tid:tid, name:name, always_return_blob:always_return_blob );
    return response;
  } else {
    #Simplified request of @ref smbntcreatex_NTLMSSP without signature verification. Used as a fallback
    tid_high = tid / 256;
    tid_low  = tid % 256;

    uid_high = uid / 256;
    uid_low  = uid % 256;

    #TBD: g_mlo and g_mhi are not set in this function
    req = raw_string( 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00, 0x00, 0x00,
                      0x00, 0x18, 0x03, 0x00, 0x50, 0x81, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      tid_low, tid_high, 0x00, 0x28, uid_low, uid_high, g_mlo, g_mhi,
                      0x18, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                      0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x9F, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                      0x00, ( strlen( name ) + 1 ) % 256, 0x00 ) + name + raw_string( 0x00 );

    req = raw_string( 0x00, 0x00, 0x00, ( strlen( req ) % 256 ) ) + req;

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( always_return_blob ) return r;
    if( strlen( r ) < 10 ) return FALSE;

    if( ord( r[9] ) == 0x00 ) {
      return r;
    } else {
      return FALSE;
    }
  }
}

# @brief Determines if SMBv1 header or SMBv2 header is used for the file access.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param name The name of the file.
# @param always_return_blob A value that determines if the signature verification is skipped and the answer is returned.
# @return Returns FALSE or NULL in case of a failure otherwise the received answer is returned.
function smbntcreatex( soc, uid, tid, name, always_return_blob ) {

  local_var soc, uid, tid, name, always_return_blob;
  local_var response;

  if( ! name ) name = "\winreg";

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smbntcreatex" );
  if( isnull( uid) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smbntcreatex" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smbntcreatex" );
  if( isnull( name ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#smbntcreatex" );

  if( strlen( uid ) == 8 ) {
    response = smb2ntcreatex( soc:soc, uid:uid, tid:tid, name:name, always_return_blob:always_return_blob );
    return response;
  } else {
    response = smb1ntcreatex( soc:soc, uid:uid, tid:tid, name:name, always_return_blob:always_return_blob );
    return response;
  }
}

# @brief Uses @ref smb1ntcreatex_NTLMSSP if ntlmssp is set or else a simplified SMBv1 version without signature verification
#        is used to create or open a file.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param name The name of the file.
# @param always_return_blob A value that determines if the signature verification is skipped and the answer is returned.
# @return Returns FALSE or NULL in case of a failure otherwise the received answer is returned.
function smb1ntcreatex( soc, uid, tid, name, always_return_blob ) {

  # ntlmssp_flag, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, name, always_return_blob;
  local_var response, tid_high, tid_low, uid_high, uid_low;

  if( ntlmssp_flag ) {
    response = smbntcreatex_NTLMSSP( soc:soc, uid:uid, tid:tid, name:name, always_return_blob:always_return_blob );
    return response;
  } else {
    tid_high = tid / 256;
    tid_low  = tid % 256;

    uid_high = uid / 256;
    uid_low  = uid % 256;

    #TBD: g_mlo and g_mhi are not set in this function
    req = raw_string( 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00, 0x00, 0x00,
                      0x00, 0x18, 0x03, 0x00, 0x50, 0x81, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      tid_low, tid_high, 0x00, 0x28, uid_low, uid_high, g_mlo, g_mhi,
                      0x18, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                      0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x9F, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                      0x00, ( strlen( name ) + 1 ) % 256, 0x00 ) + name + raw_string( 0x00 );

    req = raw_string( 0x00, 0x00, 0x00, ( strlen( req ) % 256 ) ) + req;

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( always_return_blob ) return r;
    if( strlen( r ) < 10 ) return FALSE;

    if( ord( r[9] ) == 0x00 ) {
      return r;
    } else {
      return FALSE;
    }
  }
}

# @brief Extracts the ID of a pipe or FID of a file/directory.
# @note Extract the ID of our pipe from the result of smbntcreatex() <-- Previous comment
# @param reply The reply used to extract the id of the pipe.
# @return Returns the ID of the pipe or the FID representing the file or directory.
function smbntcreatex_extract_pipe( reply ) {

  local_var reply, ret, low, high;

  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#smbntcreatex_extract_pipe" );
  if( strlen( reply ) < 44 ) return FALSE;

  if( ord( reply[4] ) == 254 ) {
    ret = smb2ntcreatex_extract_pipe( reply:reply );
    return ret;
  } else {
    low = ord( reply[42] );
    high = ord( reply[43] );
    ret = high * 256;
    ret = ret + low;
    return ret;
  }
}


# @brief Extracts the ID of a pipe when the SMBv2 header is used.
# @note Extract the ID of our pipe from the result of smbntcreatex() <-- Previous comment
#       Please see [MS-SMB2 1.1] "open" for more information.
# @param reply The reply used to extract the id of the pipe.
# @return Returns the SMB2_FILEID that is used to represent an "open" to a file.
function smb2ntcreatex_extract_pipe( reply ) {

  local_var reply, ret, start;

  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#smb2ntcreatex_extract_pipe" );
  if( strlen( reply ) < 148 ) return NULL;

  start = stridx( reply, "SMB" ); # TBD: What's the purpose of this? This will be replaced one line below again...
  # Skips the SMB2 Header --> Skips to the fileid in the SMB2 CREATE Response --> 4 is to skip the Netbios Session Service at the beginning.
  start = 64 + 64 + 4;
  #NTLMSSP challenge is 8 bytes in size
  ret = ( substr( reply, start, start + 15 ) );
  return ret;
}

# @brief Uses the SMBv1 header to determine if the registry can be accessed.
# @note Determines whether the registry is accessible <-- Previous comment
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function pipe_accessible_registry_NTLMSSP( soc, uid, tid, pipe ) {

  # s_sign_key, sign_key, isSignActive, g_mhi, g_mlo, seq_number and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe;
  local_var tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var req, len, packet, r, server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#pipe_accessible_registry_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#pipe_accessible_registry_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#pipe_accessible_registry_NTLMSSP" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#pipe_accessible_registry_NTLMSSP" );

  tid_low = tid % 256;
  tid_high = tid / 256;
  uid_low = uid % 256;
  uid_high = uid / 256;
  pipe_low = pipe % 256;
  pipe_high = pipe / 256;
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0x00, 0x00, 0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18 );
  # 0x25 is the SMB_COM_TRANSACTION command [MS-CIFS 2.2.4.33]

  if( isSignActive ) {
    req += raw_string( 0x07, 0x00 );
  } else {
    req += raw_string( 0x03, 0x00 );
  }

  req += raw_string( 0x1b, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x33, 0x0c,
                     uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x48,
                     0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x4C, 0x00, 0x48, 0x00, 0x4C, 0x00, 0x02,
                     0x00 );
  # 0x10 0x00 marks the start of the command

  # Setup and SMB_DATA are quite unclear what they are doing.
  req += raw_string( 0x26, 0x00, pipe_low, pipe_high, 0x51, 0x00, 0x5C, 0x50,
                     0x49, 0x50, 0x45, 0x5C, 0x00, 0x00, 0x00, 0x05,
                     0x00, 0x0B, 0x00, 0x10, 0x00, 0x00, 0x00, 0x48,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
                     0x16, 0x30, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
                     0xd0, 0x8c, 0x33, 0x44, 0x22, 0xF1, 0x31, 0xAA,
                     0xAA, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03, 0x01,
                     0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB,
                     0x1C, 0xc9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                     0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:packet, buflen:len, seq_number:seq_number ); # TBD: This overwrites the previous declared req...
    if( isnull( req ) ) return FALSE;
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 10 ) return FALSE;

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief This function call all the necessary functions to setup a SMB session, get an UID and a tree ID and returns them
# for further usage. This was needed to avoid code duplicates, since the same code sequence was used everywhere
# @param soc The socket used for the connection.
# @return an array containing "uid" and "tid" when successful, or NULL otherwise

function smb_login_and_get_tid_uid( soc, name, login, passwd, domain, share) {

  local_var soc, name, login, passwd, domain, share;
  local_var r, prot, uid, tid, info;

  r = smb_session_request( soc:soc, remote:name );
  if( ! r ) {
    return NULL;
  }

  prot = smb_neg_prot( soc:soc );
  if( ! prot ) {
    return NULL;
  }

  r = smb_session_setup( soc:soc, login:login, password:passwd, domain:domain, prot:prot );
  if( ! r ) {
    return NULL;
  }

  uid = session_extract_uid( reply:r );
  if( ! uid ) {
    return NULL;
  }

  r = smb_tconx( soc:soc, name:name, uid:uid, share:share );
  if( ! r ) {
    return NULL;
  }

  tid = tconx_extract_tid( reply:r );
  if( ! tid ) {
    return NULL;
  }

  r = secure_dialect_negotiation( uid:uid, tid:tid, soc:soc );
  if( r ) {
    info["uid"] = uid;
    info["tid"] = tid;
    return info;
  } else {
    return NULL;
  }
}

# @brief Uses the SMBv2 header to determine if the registry can be accessed.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function pipe2_accessible_registry_NTLMSSP( soc, uid, tid, pipe ) {

  # sign_key, isSignActive, g_mhi, g_mlo, seq_number and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe;
  local_var req, ioctl_req, sig, r, status, status2, r_head, orig_sign, server_resp, serv_sign, len, len_hi, len_lo, data;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#pipe2_accessible_registry_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#pipe2_accessible_registry_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#pipe2_accessible_registry_NTLMSSP" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#pipe2_accessible_registry_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );

  #IOCTL Req FSCTL_PIPE_TRANSCEIVE (0x00 0x11 0xc0 0x17)
  ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                          pipe, 0x78, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                          0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00,
                          0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x30, 0x16, 0x30, 0x16, 0x00, 0x00, 0x00,
                          0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                          0x00, 0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xF1,
                          0x31, 0xAA, 0xAA, 0x90, 0x00, 0x38, 0x00, 0x10,
                          0x03, 0x01, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88,
                          0x8A, 0xEB, 0x1C, 0xc9, 0x11, 0x9F, 0xE8, 0x08,
                          0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00,
                          0x00 );
  # Starting in line 5 the last 3 0x00 should be from the Buffer(Variable) field. Purpose is unclear.
  req += ioctl_req;

  #length of entire packet
  len = strlen( req );
  len_hi = len / 256;
  len_lo = len % 256;

  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#pipe2_accessible_registry_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return FALSE;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return FALSE;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;

    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr( r, 48, 63 );
    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );

    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }
  }
  # END TODO ->

  if( ord( r[12] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Determines if the SMBv2 header with ntlmssp is used to determine the access to the registry or a simplified SMBv1 version is used.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure. In case of a success the received answer is returned.
function pipe2_accessible_registry( soc, uid, tid, pipe ) {

  # ntlmssp_flag, g_mhi and g_mlo are global_vars!!!

  local_var soc, uid, tid, pipe;
  local_var response, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, req, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#pipe2_accessible_registry" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#pipe2_accessible_registry" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#pipe2_accessible_registry" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#pipe2_accessible_registry" );

  if( ntlmssp_flag ) {
    response = pipe2_accessible_registry_NTLMSSP( soc:soc, uid:uid, tid:tid, pipe:pipe );
    return response;
  } else {
    tid_low = tid % 256;
    tid_high = tid / 256;
    uid_low = uid % 256;
    uid_high = uid / 256;
    pipe_low = pipe % 256;
    pipe_high = pipe / 256;

    #TBD: g_mlo and g_mhi are not set in this function
    req = raw_string( 0x00, 0x00, 0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x00,
                      0x1B, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                      uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x48,
                      0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x4C, 0x00, 0x48, 0x00, 0x4C, 0x00, 0x02,
                      0x00, 0x26, 0x00, pipe_low, pipe_high, 0x51, 0x00, 0x5C,
                      0x50, 0x49, 0x50, 0x45, 0x5C, 0x00, 0x00, 0x00,
                      0x05, 0x00, 0x0B, 0x00, 0x10, 0x00, 0x00, 0x00,
                      0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x30, 0x16, 0x30, 0x16, 0x00, 0x00, 0x00, 0x00,
                      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                      0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xF1, 0x31,
                      0xAA, 0xAA, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03,
                      0x01, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A,
                      0xEB, 0x1C, 0xc9, 0x11, 0x9F, 0xE8, 0x08, 0x00,
                      0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 );

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 13 ) return FALSE;

    if( ord( r[12] ) == 0 ) {
      return r;
    } else {
      return FALSE;
    }
  }
}

# @brief Determines if the SMBv1 or SMBv2 header should be used to determine the if the registry can be accessed.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure. In case of a success the received answer is returned.
function pipe_accessible_registry( soc, uid, tid, pipe ) {

  local_var soc, uid, tid, pipe, res;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#pipe_accessible_registry" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#pipe_accessible_registry" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#pipe_accessible_registry" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#pipe_accessible_registry" );

  if( strlen( uid ) == 8 ) {
    res = pipe2_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
    return res;
  } else {
    res = pipe1_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
    return res;
  }
}

# @brief Determines if the SMBv1 header with ntlmssp is used to determine the access to the registry or a simplified SMBv1 version is used.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function pipe1_accessible_registry( soc, uid, tid, pipe ) {

  # ntlmssp_flag, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe;
  local_var response, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var req, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#pipe1_accessible_registry" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#pipe1_accessible_registry" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#pipe1_accessible_registry" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#pipe1_accessible_registry" );

  if( ntlmssp_flag ) {
    response = pipe_accessible_registry_NTLMSSP( soc:soc, uid:uid, tid:tid, pipe:pipe );
    return response;
  } else {
    tid_low = tid % 256;
    tid_high = tid / 256;
    uid_low = uid % 256;
    uid_high = uid / 256;
    pipe_low = pipe % 256;
    pipe_high = pipe / 256;

    #TBD: g_mlo and g_mhi are not set in this function
    req = raw_string( 0x00, 0x00, 0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x00,
                      0x1B, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                      uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x48,
                      0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x4C, 0x00, 0x48, 0x00, 0x4C, 0x00, 0x02,
                      0x00, 0x26, 0x00, pipe_low, pipe_high, 0x51, 0x00, 0x5C,
                      0x50, 0x49, 0x50, 0x45, 0x5C, 0x00, 0x00, 0x00,
                      0x05, 0x00, 0x0B, 0x00, 0x10, 0x00, 0x00, 0x00,
                      0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x30, 0x16, 0x30, 0x16, 0x00, 0x00, 0x00, 0x00,
                      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                      0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xF1, 0x31,
                      0xAA, 0xAA, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03,
                      0x01, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A,
                      0xEB, 0x1C, 0xc9, 0x11, 0x9F, 0xE8, 0x08, 0x00,
                      0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 );

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 10 ) return FALSE;

    if( ord( r[9] ) == 0 ) {
      return r;
    } else {
      return FALSE;
    }
  }
}

# @brief Determines if SMBv1 or SMBv2 header is used to open a connection to HKEY_CURRENT_USER in the Windows registry.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function registry_open_hkcu( soc, uid, tid, pipe ) {

  local_var soc, uid, tid, pipe, res, reg_type;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_open_hkcu" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_open_hkcu" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_open_hkcu" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_open_hkcu" );

  reg_type = raw_string( 0x01 ); # 0x01 => OpenHKCU

  if( strlen( uid ) == 8 ) {
    res = registry2_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  } else {
    res = registry1_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  }
}

# @brief Calls the SMBv1 or SMBv2 method for opening a connection to HKEY_CLASSES_ROOT in the Windows registry
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE or NULL in case of a failure otherwise the received answer is returned.
function registry_open_hkcr( soc, uid, tid, pipe ) {

  local_var soc, uid, tid, pipe, res, reg_type;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_open_hkcr" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_open_hkcr" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_open_hkcr" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_open_hkcr" );

  reg_type = raw_string( 0x00 ); # 0x00 => OpenHKCR

  if( strlen( uid ) == 8 ) {
    res = registry2_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  } else {
    res = registry1_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  }
}

# @brief Determines if SMBv1 or SMBv2 header is used to open a connection to HKEY_LOCAL_MACHINE in the Windows registry.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function registry_open_hklm( soc, uid, tid, pipe ) {

  local_var soc, uid, tid, pipe, res, reg_type;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_open_hklm" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_open_hklm" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_open_hklm" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_open_hklm" );

  reg_type = raw_string( 0x02 ); # 0x02 => OpenHKLM

  if( strlen( uid ) == 8 ) {
    res = registry2_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  } else {
    res = registry1_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  }
}


# @brief Determines if SMBv1 or SMBv2 header is used to open a connection to HKEY_PERFORMANCE_DATA in the Windows registry.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function registry_open_hkpd( soc, uid, tid, pipe ) {

  local_var soc, uid, tid, pipe, res, reg_type;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_open_hkpd" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_open_hkpd" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_open_hkpd" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_open_hkpd" );

  reg_type = raw_string( 0x03 ); # 0x03 => OpenHKPD

  if( strlen( uid ) == 8 ) {
    res = registry2_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  } else {
    res = registry1_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  }
}

# @brief Determines if SMBv1 or SMBv2 header is used to open a connection to HKEY_USERS in the Windows registry.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function registry_open_hku( soc, uid, tid, pipe ) {

  local_var soc, uid, tid, pipe, res, reg_type;

  reg_type = raw_string( 0x04 ); # 0x04 => OpenHKU

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_open_hku" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_open_hku" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_open_hku" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_open_hku" );

  if( strlen( uid ) == 8 ) {
    res = registry2_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  } else {
    res = registry1_open( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return res;
  }
}

# @brief Opens the registry with SMBv1 header and ntlmssp if the flag is set or with a simplified SMBv1 header and mechanism.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reg_type What registry type should be opened.
# @return Returns FALSE in case of a failure. Otherwise the received answer is returned.
function registry1_open( soc, uid, tid, pipe, reg_type ) {

  # ntlmssp_flag, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reg_type, response;
  local_var req, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry1_open" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry1_open" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry1_open" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry1_open" );
  if( isnull( reg_type ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reg_type#-#registry1_open" );

  if( ntlmssp_flag ) {
    response = registry_open_NTLMSSP( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return response;
  } else {

    tid_low = tid % 256;
    tid_high = tid / 256;
    uid_low = uid % 256;
    uid_high = uid / 256;
    pipe_low = pipe % 256;
    pipe_high = pipe / 256;

    #TBD: g_mlo and g_mhi are not set in this function
    req = raw_string( 0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x80,
                      0x1D, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                      uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x24,
                      0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x54, 0x00, 0x24, 0x00, 0x54, 0x00, 0x02,
                      0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35, 0x00, 0x00,
                      0x5c, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                      0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x5c,
                      0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                      0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0x0C, 0x00, 0x00, 0x00, 0x00, 0x00 ) + reg_type +
          raw_string( 0x00, 0x10, 0xFF, 0x12, 0x00, 0x30, 0x39, 0x01,
                      0x00, 0x00, 0x00, 0x00, 0x02 );

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 10 ) return FALSE;

    if( ord( r[9] ) == 0 ) {
      return r;
    } else {
      return FALSE;
    }
  }
}

# @brief Opens a connection to a registry using the SMBv1 header with NTLMSSP.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reg_type What registry type should be opened.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function registry_open_NTLMSSP( soc, uid, tid, pipe, reg_type ) {

  # s_sign_key, isSignActive, seq_number, multiplex_id, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reg_type;
  local_var req, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, r;
  local_var len, packet, server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_open_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_open_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_open_NTLMSSP" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_open_NTLMSSP" );
  if( isnull( reg_type ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reg_type#-#registry_open_NTLMSSP" );

  tid_low = tid % 256;
  tid_high = tid / 256;
  uid_low = uid % 256;
  uid_high = uid / 256;
  pipe_low = pipe % 256;
  pipe_high = pipe / 256;
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 0x4D,
                    0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x18 );
  #0x25 is the SMB_COM_TRANSACTION Command

  if( isSignActive ) {
    req += raw_string( 0x07, 0x80 );
  } else {
    req += raw_string( 0x03, 0x80 );
  }

  req += raw_string( 0x1D, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x33, 0x0c,
                     uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x24,
                     0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x54, 0x00, 0x24, 0x00, 0x54, 0x00, 0x02,
                     0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35, 0x00, 0x00,
                     0x5c, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                     0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x5c,
                     0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                     0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                     0x0C, 0x00, 0x00, 0x00, 0x00, 0x00 ) + reg_type +
         raw_string( 0x00, 0x10, 0xFF, 0x12, 0x00, 0x30, 0x39, 0x01,
                     0x00, 0x00, 0x00, 0x00, 0x02 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:packet, buflen:len, seq_number:seq_number );
    if( isnull( req ) ) return FALSE;
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 10 ) return FALSE;

  multiplex_id += 1;
  if( r && isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Opens the registry with SMBv2 header and ntlmssp if the flag is set or with a simplified SMBv1 header and mechanism.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reg_type What registry type should be opened.
# @return Returns FALSE in case of a failure. Otherwise the received answer is returned.
function registry2_open( soc, uid, tid, pipe, reg_type ) {

  # ntlmssp_flag, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reg_type, response;
  local_var req, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_open" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_open" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_open" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_open" );
  if( isnull( reg_type ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reg_type#-#registry2_open" );

  if( ntlmssp_flag ) {
    response = registry2_open_NTLMSSP( soc:soc, uid:uid, tid:tid, pipe:pipe, reg_type:reg_type );
    return response;
  } else {

    tid_low = tid % 256;
    tid_high = tid / 256;
    uid_low = uid % 256;
    uid_high = uid / 256;
    pipe_low = pipe % 256;
    pipe_high = pipe / 256;

    #TBD: g_mlo and g_mhi are not set in this function
    req = raw_string( 0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x80,
                      0x1D, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                      uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x24,
                      0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x54, 0x00, 0x24, 0x00, 0x54, 0x00, 0x02,
                      0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35, 0x00, 0x00,
                      0x5c, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                      0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x5c,
                      0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                      0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0x0C, 0x00, 0x00, 0x00, 0x00, 0x00 ) + reg_type +
          raw_string( 0x00, 0x10, 0xFF, 0x12, 0x00, 0x30, 0x39, 0x01,
                      0x00, 0x00, 0x00, 0x00, 0x02 );

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 10 ) return FALSE;

    if( ord( r[9] ) == 0 ) {
      return r;
    } else {
      return FALSE;
    }
  }
}

# @brief Opens a connection to a registry using the SMBv2 header with NTLMSSP.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reg_type What registry type should be opened.
# @return Returns FALSE in case of a failure otherwise the received answer is returned.
function registry2_open_NTLMSSP( soc, uid, tid, pipe, reg_type ) {

  # sign_key, isSignActive, seq_number, multiplex_id, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reg_type;
  local_var req, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, r;
  local_var ioctl_req, status, status2, r_head, orig_sign, server_resp, serv_sign, len, len_hi, len_lo, data;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_open_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_open_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_open_NTLMSSP" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_open_NTLMSSP" );
  if( isnull( reg_type ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reg_type#-#registry2_open_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );

  # IOCTL FSCTL_PIPE_TRANSCEIVE [MS-SMB2 2.2.31]
  ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                          pipe, 0x78, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                          0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00,
                          0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                          0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00 ) + reg_type +
              raw_string( 0x00, 0x10, 0xFF, 0x12, 0x00, 0x30, 0x39, 0x01,
                          0x00, 0x00, 0x00, 0x00, 0x02 );
  # Starting with 0x05 0x00 0x00 0x03 we have DCE/RPC Request
  # Starting with 0x10 0xFF we have Remote Registry Service

  req += ioctl_req;

  #length of entire packet
  len = strlen( req );
  len_hi = len / 256;
  len_lo = len % 256;

  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_open_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return NULL;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return NULL;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  multiplex_id += 1;
  if( isSignActive ) {

    seq_number += 1;
    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr( r, 48, 63 );
    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );

    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }

  }
  # END TODO ->

  if( ord( r[12] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Closes the key in the registry after it was opened using the SMBv1 header with ntlmssp.
# @note RegClose() NTLMSSP <-- Previous comment
#       More examination regarding the return value is required.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE in case of a failure. If successful it is likely that the status code is returned.
function registry_close_NTLMSSP( soc, uid, tid, pipe, reply ) {

  # s_sign_key, isSignActive, seq_number, multiplex_id, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reply;
  local_var tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, magic, i;
  local_var req, len, packet, r, server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_close_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_close_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_close_NTLMSSP" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_close_NTLMSSP" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry_close_NTLMSSP" );

  tid_low = tid % 256;
  tid_high = tid / 256;

  uid_low = uid % 256;
  uid_high = uid / 256;

  pipe_low = pipe % 256;
  pipe_high = pipe / 256;

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  if( strlen( reply ) < 85 ) return FALSE ;

  magic = raw_string( ord( reply[84] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 84 + i ) ) {
      magic += raw_string( ord( reply[84+i] ) );
    }
  }

  req = raw_string( 0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x08 );

  if( isSignActive ) {
    req += raw_string( 0x05, 0x40 );
  } else {
    req += raw_string( 0x01, 0x40 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x33, 0x0c,
                     uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2c,
                     0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x4c, 0x00, 0x2c, 0x00, 0x4c, 0x00, 0x02,
                     0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35, 0x00, 0x5c,
                     0x50, 0x49, 0x50, 0x45, 0x5c, 0x00, 0x00, 0x00,
                     0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                     0x2c, 0x00, 0x00, 0x00, 0xcf, 0x01, 0x00, 0x00,
                     0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00 ) + magic;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:packet, buflen:len, seq_number:seq_number ); # TBD: This overwrites the previous declared req...
    if( isnull( req ) ) return FALSE;
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );

  multiplex_id += 1;
  if( r && isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;

    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( r && ( strlen( r ) > 4 ) ) {
    return( substr( r, strlen( r ) - 4, strlen( r ) - 1 ) );
  } else {
    return FALSE;
  }
}

# @brief Closes the key in the registry after it was opened using the SMBv2 header with ntlmssp.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE in case of a failure. If successful the status named "Windows Error" from the Remote Registry Service is returned.
function registry2_close_NTLMSSP( soc, uid, tid, pipe, reply ) {

  # sign_key, isSignActive, seq_number, multiplex_id, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reply;
  local_var ioctl_req, dcerpc_req1, dcerpc_req2, magic, i;
  local_var rrs_req, len_rrs, len_rss_lo, len_rrs_hi, dcerpc_req, req;
  local_var req_l, len_lo, len_hi, sig, r, status, status2;
  local_var r_head, orig_sign, server_resp, serv_sign, data;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_close_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_close_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_close_NTLMSSP" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_close_NTLMSSP" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry2_close_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );

  # Ioctl Req
  ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                          pipe, 0x78, 0x00, 0x00, 0x00 );

  # Distributed Computing Environment / Remote Procedure Calls
  dcerpc_req1 = raw_string( 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00 );
  dcerpc_req2 = raw_string( 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x05, 0x00 );

  if( strlen( reply ) < 140 ) return FALSE ;
  magic = raw_string( ord( reply[140] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 140 + i ) ) {
      magic += raw_string( ord( reply[140+i] ) );
    }
  }

  # Remote Registry Service Req
  rrs_req = magic ;

  len_rrs = strlen( rrs_req ) + strlen( dcerpc_req1 ) + strlen( dcerpc_req2 ) + 2;
  len_rrs_lo = len_rrs % 256;
  len_rrs_hi = len_rrs / 256;

  dcerpc_req = dcerpc_req1 + raw_string( len_rrs_lo, len_rrs_hi ) + dcerpc_req2;

  ioctl_req += raw_string( len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00 );

  req = req + ioctl_req + dcerpc_req + rrs_req;
  req_l = strlen( req );
  len_lo =  req_l % 256;
  len_hi = req_l / 256;

  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_close_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return FALSE;

  ##If status is pending, wait for response
  status = ord(r[12]);
  status2 = ord(r[13]);
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv(socket:soc);
    if( strlen( r ) < 14 ) return FALSE;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  multiplex_id += 1;
  if( r && isSignActive ) {
    # verify signature
    seq_number += 1;

    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr(r, 48, 63);

    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );

    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }
  }
  # END TODO ->

  if( r && ( strlen( r ) > 4 ) ) {
    return( substr( r, strlen( r ) - 4, strlen( r ) - 1 ) );
  } else {
    return FALSE;
  }
}

# @brief Determines if the SMBv1 or SMBv2 header should be used to close the access to a key in the registry.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns false in case of a failure otherwise the received status is returned.
function registry_close( soc, uid, tid, pipe, reply ) {

  local_var soc, uid, tid, pipe, reply, res;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_close" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_close" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_close" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_close" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry_close" );

  if( strlen( uid ) == 8 ) {
    res = registry2_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return res;
  } else {
    res = registry1_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return res;
  }
}

# @brief Determines if the SMBv1 header with NTLMSSP should be used to close the registry or a simplified SMBv1 header without ntlmssp is used.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns false in case of a failure otherwise the received status is returned.
function registry1_close( soc, uid, tid, pipe, reply ) {

  # ntlmssp_flag, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reply;
  local_var response, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var magic, i, req, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry1_close" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry1_close" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry1_close" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry1_close" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry1_close" );

  if( ntlmssp_flag ) {
    response = registry_close_NTLMSSP( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return response;
  } else {
    tid_low = tid % 256;
    tid_high = tid / 256;
    uid_low = uid % 256;
    uid_high = uid / 256;
    pipe_low = pipe % 256;
    pipe_high = pipe / 256;

    if( strlen( reply ) < 85 ) return FALSE ;
    magic = raw_string( ord( reply[84] ) );
    for( i = 1; i < 20; i++ ) {
      if( strlen( reply ) > ( 84 + i ) ) {
        magic += raw_string( ord( reply[84+i] ) );
      }
    }

    req = raw_string( 0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                      uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2c,
                      0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x4c, 0x00, 0x2c, 0x00, 0x4c, 0x00, 0x02,
                      0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35, 0x00, 0x5c,
                      0x50, 0x49, 0x50, 0x45, 0x5c, 0x00, 0x00, 0x00,
                      0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                      0x2c, 0x00, 0x00, 0x00, 0xcf, 0x01, 0x00, 0x00,
                      0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00 ) + magic;

    send( socket:soc, data:req );
    r = smb_recv(socket:soc);
    if( r && ( strlen( r ) > 4 ) ) {
      return substr( r, strlen( r ) - 4, strlen( r ) - 1 );
    } else {
      return FALSE;
    }
  }
}


# @brief Determines if the SMBv2 header with NTLMSSP should be used to close the registry or a simplified SMBv1 header without ntlmssp is used.
# @note ###SMB2 Registry close##### <-- Previous comment
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns false in case of a failure otherwise the received status is returned.
function registry2_close( soc, uid, tid, pipe, reply ) {

  # ntlmssp_flag, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reply;
  local_var response, magic, i, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_close" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_close" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_close" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_close" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry2_close" );

  if( ntlmssp_flag ) {
    response = registry2_close_NTLMSSP( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return response;
  } else {
    if( strlen( reply ) < 85 ) return FALSE ;

    magic = raw_string( ord( reply[84] ) );
    for( i = 1; i < 20; i++ ) {
      if( strlen( reply ) > ( 84 + i ) ) {
        magic += raw_string( ord( reply[84+i] ) );
      }
    }

    tid_low = tid % 256;
    tid_high = tid / 256;
    uid_low = uid % 256;
    uid_high = uid / 256;
    pipe_low = pipe % 256;
    pipe_high = pipe / 256;

    req = raw_string( 0x00, 0x00, 0x00, 0x78, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                      uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2c,
                      0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x4c, 0x00, 0x2c, 0x00, 0x4c, 0x00, 0x02,
                      0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35, 0x00, 0x5c,
                      0x50, 0x49, 0x50, 0x45, 0x5c, 0x00, 0x00, 0x00,
                      0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                      0x2c, 0x00, 0x00, 0x00, 0xcf, 0x01, 0x00, 0x00,
                      0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00 ) + magic;
    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( r && ( strlen( r ) > 4 ) ) {
      return substr( r, strlen( r ) - 4, strlen( r ) - 1 );
    } else {
      return FALSE;
    }
  }
}

# @brief Decides if the SMBv1 or SMBv2 header should be used to enumerate a subkey.
# @note RegEnumKey() <-- Previous comment
#       [MS-RPP 3.1.5.10]
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE or NULL in case of a failure. If successful a list with the subkey is returned.
function registry_enum_key( soc, uid, tid, pipe, reply ) {

  local_var soc, uid, tid, pipe, reply, res;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_enum_key" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_enum_key" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_enum_key" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_enum_key" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry_enum_key" );

  if( strlen( uid ) == 8 ) {
    res = registry2_enum_key( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return res;
  } else {
    res = registry1_enum_key( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return res;
  }
}

# @brief Uses the SMBv2 header to enumerate a subkey. The server returns the requested subkey.
# @note RegEnumKey() <-- Previous comment
#       [MS-RPP 3.1.5.10]
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE or NULL in case of a failure. If successful a list with the subkey is returned.
function registry2_enum_key( soc, uid, tid, pipe, reply ) {

  # sign_key, isSignActive, seq_number, multiplex_id, g_mlo and g_mhi are global_vars!!!

  local_var soc, uid, tid, pipe, reply;
  local_var list, magic, i, j, req, ioctl_req, dcerpc_req1, dcerpc_req2;
  local_var rrs_req, len_rrs, len_rrs_lo, len_rrs_hi, dcerpc_req, req_l, len_lo, len_hi;
  local_var sig, r, status, status2, r_head, orig_sign, server_resp, serv_sign, len, name, data;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_enum_key" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_enum_key" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_enum_key" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_enum_key" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry2_enum_key" );

  list = make_list();

  if( strlen( reply ) < 141 ) return NULL ;

  magic = raw_string( ord( reply[140] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 140 + i ) ) {
      magic += raw_string( ord( reply[140+i] ) );
    }
  }

  for( j = 0; j >= 0; j++ ) {

    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;

    req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );

    if( isSignActive ) {
      req += raw_string( 0x08, 0x00, 0x00, 0x00 );
    } else {
      req += raw_string( 0x00, 0x00, 0x00, 0x00 );
    }

    req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00 );

    # Ioctl Req FSCTL_PIPE_TRANSCEIVE
    ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                            pipe, 0x78, 0x00, 0x00, 0x00 );

    # Distributed Computing Environment / Remote Procedure Calls
    dcerpc_req1 = raw_string( 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00 );
    dcerpc_req2 = raw_string( 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x09, 0x00 );
    # 0x09 is the opnum and means to enumerate a subkey [MS-RRP 3.1.5.10]

    # Remote Registry Service Req
    rrs_req = magic + raw_string( j % 256, j / 256, 0x00, 0x00,  # key ID
                                  0x00, 0x00,     # key name len
                                  0x14, 0x04,      # unknown
                                  0x01, 0x00, 0x00, 0x00,   # ptr
                                  0x0a, 0x02, 0x00, 0x00,   # unknown_2
                                  0x00, 0x00, 0x00, 0x00,   # padding
                                  0x00, 0x00, 0x00, 0x00,   # padding
                                  0x01, 0x00, 0x00, 0x00,   # ptr2
                                  0x00, 0x00, 0x00, 0x00,   # padding2
                                  0x00, 0x00, 0x00, 0x00,   # padding2
                                  0x01, 0x00, 0x00, 0x00,   # ptr3
                                  0xff, 0xff, 0xff, 0xff,   # smb_io_time low
                                  0xff, 0xff, 0xff, 0x7f ); # smb_io_time high

    len_rrs = strlen( rrs_req ) + strlen( dcerpc_req1 ) + strlen( dcerpc_req2 ) + 2;
    len_rrs_lo = len_rrs % 256;
    len_rrs_hi = len_rrs / 256;

    dcerpc_req = dcerpc_req1 + raw_string( len_rrs_lo, len_rrs_hi ) + dcerpc_req2;

    ioctl_req += raw_string( len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00 );

    req = req + ioctl_req + dcerpc_req + rrs_req;
    req_l = strlen(req);
    len_lo =  req_l % 256;
    len_hi = req_l / 256;

    if( isSignActive ) {
      if( smbv3 ) {
        sig = smb_cmac_aes_signature( buf:req, key:sign_key );
      } else if ( smbv2 ) {
        sig = get_smb2_signature( buf:req, key:sign_key );
      }
      if( isnull( sig ) ) {
        set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_enum_key: buf or key passed to signature function empty / too short" );
        return FALSE;
      }
      data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
    } else {
      data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
    }

    if( smbEncryption ) {
      data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
    }
    # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
    send( socket:soc, data:data );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return NULL;

    ##If status is pending, wait for response
    status = ord(r[12]);
    status2 = ord(r[13]);
    while( status == 3 && status2 == 1 ) {
      ##PDU will arrive late
      r = smb_recv( socket:soc );
      if( strlen( r ) < 14 ) return NULL;
      status = ord( r[12] );
      status2 = ord( r[13] );
    }

    if( strlen( r ) < 80 ) return NULL;

    multiplex_id += 1;
    if( isSignActive ) {
      # verify signature
      seq_number += 1;

      r_head = substr( r, 0, 3 );
      r = substr( r, 4, strlen( r ) - 1 );
      if( strlen( r ) < 64 ) return FALSE;

      orig_sign = substr( r, 48, 63 );

      if( smbv3 ) {
        server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
      } else if( smbv2 ) {
        server_resp = get_smb2_signature( buf:r, key:sign_key );
      }
      if( isnull( server_resp ) ) return FALSE;
      if( strlen( server_resp ) < 64 ) return FALSE;

      serv_sign = substr( server_resp, 48, 63 );
      if( orig_sign != serv_sign ) {
        return FALSE;
      } else {
        r = r_head + r;
      }
    }
    # END TODO ->

    if( strlen( r ) > 156 ) {
      len = ord( r[156] );
      if( ! len ) break;
    } else {
      break;
    }

    name = "";
    for( i = 0; i < len - 1; i++ ) {
      if( strlen( r ) > ( 159 + i * 2 + 1 ) ) {
        name += r[159+i*2+1];
      }
    }
    list = make_list( list, name );
  }
  return list;
}

# @brief Uses the SMBv1 header to enumerate a subkey. The server returns the requested subkey.
# @note RegEnumKey() <-- Previous comment
#       [MS-RPP 3.1.5.10]
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE or NULL in case of a failure. If successful a list with the subkey is returned.
function registry1_enum_key( soc, uid, tid, pipe, reply ) {

  # isSignActive, ntlmssp_flag, seq_number, s_sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, reply;
  local_var list, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var magic, i, j, req, req2, len, packet, r, server_resp, orig_sign, serv_sign, name;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry1_enum_key" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry1_enum_key" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry1_enum_key" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry1_enum_key" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry1_enum_key" );

  list = make_list();
  tid_low = tid % 256;
  tid_high = tid / 256;

  uid_low = uid % 256;
  uid_high = uid / 256;

  pipe_low = pipe % 256;
  pipe_high = pipe / 256;

  if( strlen( reply ) < 85 ) return NULL;

  magic = raw_string( ord( reply[84] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 84 + i ) ) {
      magic += raw_string( ord( reply[84+i] ) );
    }
  }

  for( j = 0; j >= 0; j++ ) {

    req = raw_string( 0x00, 0x00, 0x00, 0xa8, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x08 );
    # 0x25 is the SMB_COM_TRANSACTION command [MS-CIFS 2.2.4.33]

    if( isSignActive ) {
      req += raw_string( 0x05, 0x40 );
    } else {
      req += raw_string( 0x01, 0x40 );
    }

    req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, tid_low, tid_high );

    if( ntlmssp_flag ) {
      req += raw_string( 0x33, 0x0c );
    } else {
      req += raw_string( 0x00, 0x28 );
    }

    req += raw_string( uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x5c,
                       0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x4c, 0x00, 0x5c, 0x00, 0x4c, 0x00, 0x02,
                       0x00, 0x26, 0x00, pipe_low, pipe_high, 0x65, 0x00, 0x5c,
                       0x50, 0x49, 0x50, 0x45, 0x5c, 0x00, 0x00, 0x00,
                       0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                       0x5c, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
                       0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00 );
    # In the third last line 0x05 0x00 0x00 0x03 the DCE/RPC started.
    # It again is using opnum 0x09 and request the enumeration of a subkey.
    # [MS-RPP 3.1.5.10]

    req2 = magic + raw_string( j % 256, j / 256, 0x00, 0x00, # key ID
                               0x00, 0x00,                   # key name len
                               0x14, 0x04,                   # unknown
                               0x01, 0x00, 0x00, 0x00,       # ptr
                               0x0a, 0x02, 0x00, 0x00,       # unknown_2
                               0x00, 0x00, 0x00, 0x00,       # padding
                               0x00, 0x00, 0x00, 0x00,       # padding
                               0x01, 0x00, 0x00, 0x00,       # ptr2
                               0x00, 0x00, 0x00, 0x00,       # padding2
                               0x00, 0x00, 0x00, 0x00,       # padding2
                               0x01, 0x00, 0x00, 0x00,       # ptr3
                               0xff, 0xff, 0xff, 0xff,       # smb_io_time low
                               0xff, 0xff, 0xff, 0x7f );     # smb_io_time high

    req += req2;

    # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
    if( ntlmssp_flag && isSignActive ) {
      len = strlen( req );
      seq_number += 1;
      packet = req;
      req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
      if( isnull( req ) ) return FALSE;
    }

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 80 ) return NULL;

    if( ntlmssp_flag ) {
      multiplex_id += 1;
      if( r && isSignActive ) {
        # verify signature
        seq_number += 1;
        len = strlen( r );
        server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
        if( isnull( server_resp ) ) return FALSE;
        if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
          return FALSE;
        }
        orig_sign = substr( r, 18, 23 );
        serv_sign = substr( server_resp, 18, 23 );
        if( orig_sign != serv_sign ) {
          return FALSE;
        }
      }
    }
    # -> END TODO

    if( strlen( r ) > 100 ) {
      len = ord( r[60+24+16] );
      if( ! len ) break;
    } else {
      break;
    }

    name = "";
    for( i = 0; i < len - 1; i++ ) {
      if( strlen( r ) > ( 60 + 43 + i * 2 + 1 ) ) {
        name += r[60+43+i*2+1];
      }
    }
    list = make_list( list, name );
  }
  return list;
}

# @brief Changes a decimal number to a decimal value.
# @note Required for registry2_enum_value() <-- Previous comment
# @author Shakeel (bshakeel@secpod.com)
# @param num The decimal number that needs to be converted.
# @return The hexadecimal value of the decimal number.
function decimal_to_hexadecimal(num) {
  local_var num;
  if( isnull( num ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#num#-#decimal_to_hexadecimal" );

  if(num ==0) {
    number = raw_string( 0x00 );
  } else {
    while (num != 0)
    {
      rem=num%256;
      number = raw_string(rem, number);
      num=num/256;
    }
  }
  return number ;
}

# @brief Changes from the endian of a given hexnumber
# @note Author: Shakeel (bshakeel@secpod.com)
#       Required for registry2_enum_value() <-- Previous comment
# @param hexanumber The number which endianness should be changend.
# @return Returns 0x00 in case dependencies are not met otherwise always a 4byte word with changend endian is returned.
function endianness_change_hexadecimal(hexanumber) {

  local_var dec_index, res_index, enumindex, hexanumber;
  if( isnull( hexanumber ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#hexanumber#-#endianness_change_hexadecimal" );

  ## http_func.inc is dependency to be included in VT for hex2dec()
  dec_index = hex2dec(xvalue:hexstr(hexanumber));
  if(dec_index) {
    x1 = (dec_index & 0xff) << 24;
    x2 = (dec_index & 0xff00) << 8 ;
    x3 = (dec_index & 0xff0000) >> 8 ;
    x4 = (dec_index >> 24) & 0xff;
    res_index = x1 | x2 | x3 | x4 ;
    enumindex = decimal_to_hexadecimal(num:res_index);

    if(enumindex) {
      ## Make it again 4-byte
      if(strlen(enumindex) == 3) {
        enumindex = raw_string( 0x00, enumindex);
      }
      else if (strlen(enumindex) == 2) {
        enumindex = raw_string( 0x00,0x00, enumindex);
      }
      else if (strlen(enumindex) == 1) {
        enumindex = raw_string( 0x00,0x00,0x00, enumindex);
      }
      return enumindex ;
    }
  }
  return (raw_string(0x00));
}



# @brief Uses the SMBv2 header to send a IOCTL so the server enumerates a value for a key at a specific index.
# @note RegEnumValue() for SMB 2
#       Author: Shakeel (bshakeel@secpod.com) <-- Previous comment
#       [MS-RPP 3.1.5.11]
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE or NULL in case of a failure. If successful the value and data at the specified index for the specified key.
function registry2_enum_value( soc, uid, tid, pipe, reply ) {

  local_var soc, uid, tid, pipe, reply;
  local_var list, magic, i, j, req, ioctl_req, dcerpc_req1, dcerpc_req2;
  local_var rrs_req, len_rrs, len_rrs_lo, len_rrs_hi, dcerpc_req, req_l, len_lo, len_hi, data;
  local_var sig, r, status, status2, r_head, orig_sign, server_resp, serv_sign, len, name;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_enum_value" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_enum_value" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_enum_value" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_enum_value" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry2_enum_value");

  list = make_list();

  if( strlen( reply ) < 141 ) return NULL;

  # The received handle
  magic = raw_string( ord( reply[140] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 140 + i ) ) {
      magic += raw_string( ord( reply[140+i] ) );
    }
  }

  ##Enumerate for index
  for( j = 0; j >= 0; j++ ) {
    enumindex = decimal_to_hexadecimal(num:j);
    if(strlen(enumindex) == 1) {
      enumindex = raw_string( enumindex, 0x00, 0x00, 0x00);
    } else if(strlen(enumindex) == 2) {

      ##Construct 4-byte index
      enumindex = raw_string( 0x00, 0x00, enumindex);

      ## Change Endianness of 4-byte index, http_func.inc is dependency to be included in VT for hex2dec()
      enumindex = endianness_change_hexadecimal(hexanumber:enumindex);

    } else if(strlen(enumindex) == 3) {
      ##Construct 4-byte index
      enumindex = raw_string( 0x00, enumindex);

      ## Change Endianness of 4-byte index, http_func.inc is dependency to be included in VT for hex2dec()
      enumindex = endianness_change_hexadecimal(hexanumber:enumindex);

    } else if(strlen(enumindex) == 4) {
      enumindex = raw_string( enumindex);

      ## Change Endianness of 4-byte index, http_func.inc is dependency to be included in VT for hex2dec()
      enumindex = endianness_change_hexadecimal(hexanumber:enumindex);
    }

    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;

    req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );

    if( isSignActive ) {
      req += raw_string( 0x08, 0x00, 0x00, 0x00 );
    } else {
      req += raw_string( 0x00, 0x00, 0x00, 0x00 );
    }

    req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00 );

    # Ioctl Req FSCTL_PIPE_TRANSCEIVE
    ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                            pipe, 0x78, 0x00, 0x00, 0x00 );

    # Distributed Computing Environment / Remote Procedure Calls
    dcerpc_req1 = raw_string( 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00 );
    dcerpc_req2 = raw_string( 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x0A, 0x00 );
    # Opnum is 0x0A = 10 so we call BaseRegEnumValue
    # The server enumerates the value at the specified index for the specified registry key
    # [MS-RPP 3.1.5.11]



    # Remote Registry Service Req
    rrs_req = magic + enumindex;            # Enum Index

    rrs_req = rrs_req + raw_string( 0x00, 0x00, 0x14, 0x04, 0x01, 0x00, 0x00,
                                    0x00, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);       # PTR Name

    rrs_req = rrs_req + raw_string(0x00, 0x00, 0x00, 0x00, # Type
                                  0x00, 0x00, 0x00, 0x00,  # Value
                                  0x00, 0x00, 0x00, 0x00,  # Size
                                  0x00, 0x00, 0x00, 0x00); # Length

    len_rrs = strlen( rrs_req ) + strlen( dcerpc_req1 ) + strlen( dcerpc_req2 ) + 2;
    len_rrs_lo = len_rrs % 256;
    len_rrs_hi = len_rrs / 256;

    dcerpc_req = dcerpc_req1 + raw_string( len_rrs_lo, len_rrs_hi ) + dcerpc_req2;

    ioctl_req += raw_string( len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00 );
    req = req + ioctl_req + dcerpc_req + rrs_req;
    req_l = strlen(req);
    len_lo =  req_l % 256;
    len_hi = req_l / 256;

    if( isSignActive ) {
      if( smbv3 ) {
        sig = smb_cmac_aes_signature( buf:req, key:sign_key );
      } else if ( smbv2 ) {
        sig = get_smb2_signature( buf:req, key:sign_key );
      }
      if( isnull( sig ) ) {
        set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_enum_key: buf or key passed to signature function empty / too short" );
        return FALSE;
      }
      data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
    } else {
      data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
    }

    if( smbEncryption ) {
      data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
    }
    # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
    send( socket:soc, data:data );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return NULL;

    ##If status is pending, wait for response
    status = ord(r[12]);
    status2 = ord(r[13]);
    while( status == 3 && status2 == 1 ) {
      ##PDU will arrive late
      r = smb_recv( socket:soc );
      if( strlen( r ) < 14 ) return NULL;
      status = ord( r[12] );
      status2 = ord( r[13] );
    }

    if( strlen( r ) < 80 ) return NULL;

    multiplex_id += 1;
    if( isSignActive ) {
      # verify signature
      seq_number += 1;

      r_head = substr( r, 0, 3 );
      r = substr( r, 4, strlen( r ) - 1 );
      if( strlen( r ) < 64 ) return FALSE;

      orig_sign = substr( r, 48, 63 );

      if( smbv3 ) {
        server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
      } else if( smbv2 ) {
        server_resp = get_smb2_signature( buf:r, key:sign_key );
      }
      if( isnull( server_resp ) ) return FALSE;
      if( strlen( server_resp ) < 64 ) return FALSE;

      serv_sign = substr( server_resp, 48, 63 );
      if( orig_sign != serv_sign ) {
        return FALSE;
      } else {
        r = r_head + r;
      }
    }
    # END TODO ->
    if( strlen( r ) > 156 ) {
      len = ord( r[156] );
      if( ! len ) break;
    } else {
      break;
    }

    name = "";
    for( i = 0; i < len - 1; i++ ) {
      if( strlen( r ) > ( 159 + i * 2 + 1 ) ) {
        name += r[159+i*2+1];
      }
    }
    list = make_list( list, name );
  }
  return list;
}


# @brief Uses the SMBv1 header to send a command so the server enumerates a value for a key at a specific index.
# @note RegEnumValue()
#       Author: Nicolas Pouvesle <-- Previous comment
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE or NULL in case of a failure. If successful the value and data at the specified index for the specified key.
function registry1_enum_value( soc, uid, tid, pipe, reply ) {

  # isSignActive, ntlmssp_flag, seq_number, s_sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, reply;
  local_var tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var magic, i, j, req, len, packet, r, server_resp, orig_sign, serv_sign, name;
  local_var dlen, data;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry1_enum_value" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry1_enum_value" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry1_enum_value" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry1_enum_value" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry1_enum_value" );

  tid_low = tid % 256;
  tid_high = tid / 256;

  uid_low = uid % 256;
  uid_high = uid / 256;

  pipe_low = pipe % 256;
  pipe_high = pipe / 256;

  if( strlen( reply ) < 85 ) return FALSE ;

  # The received handle
  magic = raw_string( ord(reply[84] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 84 + i ) ) {
      magic += raw_string( ord( reply[84+i] ) );
    }
  }

  for( j = 0; j >= 0; j++ ) {

    req = raw_string( 0x00, 0x00, 0x00, 0xC0, 0xFF, 0x53, 0x4D, 0x42,
                      0x25, 0x00, 0x00, 0x00, 0x00, 0x18 );
    # 0x25 is the SMB_COM_TRANSACTION command.

    if( ntlmssp_flag ) {
      g_mhi = multiplex_id / 256;
      g_mlo = multiplex_id % 256;

      if( isSignActive ) {
        req += raw_string( 0x07, 0x80 );
      } else {
        req += raw_string( 0x03, 0x80 );
      }
    } else {
      req += raw_string(0x03, 0x80);
    }

    req += raw_string( 0x00, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, tid_low, tid_high );

    if( ntlmssp_flag ) {
      req += raw_string( 0x33, 0x0c );
    } else {
      req += raw_string( 0x00, 0x28 );
    }

    req += raw_string( uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x6C,
                       0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x54, 0x00, 0x6C, 0x00, 0x54, 0x00, 0x02,
                       0x00, 0x26, 0x00, pipe_low, pipe_high, 0x59, 0x00, 0x00,
                       0x5C, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                       0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0xEE, 0xD5,
                       0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                       0x6C, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                       0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00 );
    # 0x05 0x00 0x00 0x03 is the start of the DCE/RPC before that is the SMBv1 header and the command
    # Opnum is 0x0A = 10 so we call BaseRegEnumValue
    # The server enumerates the value at the specified index for the specified registry key
    # [MS-RPP 3.1.5.11]

    req = req + magic + raw_string( j % 256, j / 256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                    0xcc, 0xf9, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0xa0, 0xf9, 0x06, 0x00, 0x59, 0xe6, 0x07, 0x00,
                                    0x00, 0xc4, 0x04, 0x01, 0x00, 0x80, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0xb0, 0xf9, 0x06, 0x00, 0x00, 0x80, 0x00, 0x00,
                                    0x94, 0xf9, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 );

    # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
    if( ntlmssp_flag && isSignActive ) {
      len = strlen( req );
      seq_number += 1;
      packet = req;
      req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
      if( isnull( req ) ) return FALSE;
    }

    send( socket:soc, data:req );
    r = smb_recv( socket:soc );
    if( strlen( r ) < 80 ) return NULL;

    if( ntlmssp_flag ) {
      multiplex_id += 1;
      if( r && isSignActive ) {
        # verify signature
        seq_number += 1;
        len = strlen( r );
        server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
        if( isnull( server_resp ) ) return FALSE;
        if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
          return FALSE;
        }

        orig_sign = substr( r, 18, 23 );
        serv_sign = substr( server_resp, 18, 23 );
        if( orig_sign != serv_sign ) {
          return FALSE;
        }
      }
    }
    # -> END TODO

    if( strlen( r ) > 84 ) {
      len = ord( r[60+24] );
      if( ! len ) break;
    } else {
      break;
    }

    name = "";
    for( i = 0; i < len; i = i + 2 ) {
      if( strlen( r ) > ( 60 + 43 + i + 1 ) ) {
        name += r[60+43+i+1];
      }
    }

    if( strlen( r ) > ( 60 + 43 + len + 2 ) ) {
      if( ! ord( r[60+43+len+2] ) ) {
        len += 2;
      }
    } else {
      len += 2;
    }

    if( strlen( r ) > ( 60 + 43 + len + 21 ) ) {
      dlen = ord( r[60+43+len+21] );
    }

    data = "";
    for( i = 0; i < dlen; i = i + 2 ) {
      if( strlen( r ) > ( 60 + 43 + len + 24 + i + 1 ) ) {
        data += r[60+43+len+24+i+1];
      }
    }

    list[j*2] = name;
    list[j*2+1] = data;
  }
  return list;
}

# @brief Decides if the SMBv1 or SMBv2 header should be used to send a IOCTL so the server enumerates a value for a key at a specific index.
# @param soc The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree.
# @param pipe The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param reply The reply after a registry key was opened.
# @return Returns FALSE or NULL in case of a failure. If successful the value and data at the specified index for the specified key.
function registry_enum_value( soc, uid, tid, pipe, reply ) {

  local_var soc, uid, tid, pipe, item, reply, res;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_enum_value" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_enum_value" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_enum_value" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_enum_value" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry_enum_value" );

  if( strlen( uid ) == 8 ) {
    res = registry2_enum_value( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return res;
  } else {
    res = registry1_enum_value( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply );
    return res;
  }
}

# @brief Implementation of RegOpenKey() to open a specific registry key on the remote registry
#        of the target. The function is mostly called internally by other functions like @ref registry_enum_keys
#        or @ref registry_key_exists.
#
# @param soc   The TCP socket for the current connection
# @param uid   The session id,
# @param tid   The id of a tree.
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param key   The specific key to open, e.g. "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
# @param reply The reply after a registry key was opened. E.g. @ref registry_open_hklm
#
# @note Functions calling this function should close the handle via @ref registry_close in a form like:
#
#       r = registry_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle );
#       if( ! isnull( r ) registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );
#
# @return The handle to the opened registry-key (in binary form) for later use within other functions,
#         FALSE if the registry key doesn't exist and NULL if any of the mandatory function parameters
#         are missing or the connection to the registry or opening the specific registry key failed
#         due to e.g. connectivity issues or permission problems.
#
function registry_get_key( soc, uid, tid, pipe, key, reply ) {

  local_var soc, uid, tid, pipe, key, reply, res;

  if( isnull( soc ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_get_key" );
    return NULL;
  }

  if( isnull( uid ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_get_key" );
    return NULL;
  }

  if( isnull( tid ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_get_key" );
    return NULL;
  }

  if( isnull( pipe ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_get_key" );
    return NULL;
  }

  if( isnull( key ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry_get_key" );
    return NULL;
  }

  if( isnull( reply ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry_get_key" );
    return NULL;
  }

  if( strlen( uid ) == 8 ) {
    res = registry2_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:reply );
    return res;
  } else {
    res = registry1_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:reply );
    return res;
  }
}

# @brief internal function for SMBv1 which shouldn't be called directly, please see @ref registry_get_key
#        for a description.
# @param soc   The socket used for the connection.
# @param uid   The session id.
# @param tid   The id of the tree.
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param key   The specific key to open, e.g. "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
# @param reply The reply after a registry key was opened. E.g. @ref registry_open_hklm
# @param write Could be used to write to a key, but the value is never set.
# @return Returns NULL if a failure occurs and FALSE it the NT_STATUS does not match.
#         On a successful response the response is returned.
function registry1_get_key( soc, uid, tid, pipe, key, reply, write ) {

  # isSignActive, ntlmssp_flag, seq_number, s_sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, key, reply, write;
  local_var key_len, key_len_hi, key_len_lo, tid_low, tid_high;
  local_var uid_low, uid_high, pipe_low, pipe_high, uc, access_mask;
  local_var len, len_hi, len_lo, z, z_lo, z_hi, y, y_lo, y_hi, x, x_lo, x_hi;
  local_var magic1, req, magic, packet, r, server_resp, orig_sign, serv_sign;
  local_var _na_start, _na_cnt, _na_data;

  if( isnull( soc ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry1_get_key" );
    return NULL;
  }

  if( isnull( uid ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry1_get_key" );
    return NULL;
  }

  if( isnull( tid ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry1_get_key" );
    return NULL;
  }

  if( isnull( pipe ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry1_get_key" );
    return NULL;
  }

  if( isnull( key ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry1_get_key" );
    return NULL;
  }

  if( isnull( reply ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry1_get_key" );
    return NULL;
  }

  key_len = strlen( key ) + 1;
  key_len_hi = key_len / 256;
  key_len_lo = key_len % 256;

  tid_low = tid % 256;
  tid_high = tid / 256;
  uid_low = uid % 256;
  uid_high = uid / 256;
  pipe_low = pipe % 256;
  pipe_high = pipe / 256;
  uc = unicode( data:key );

  if( write ) {
    access_mask = raw_string( 0x19, 0x00, 0x02, 0x02 );
  } else {
    access_mask = raw_string( 0x19, 0x00, 0x02, 0x00 );
  }

  uc += access_mask;
  len = 148 + strlen( uc );

  len_hi = len / 256;
  len_lo = len % 256;

  z = 40 + strlen( uc );
  z_lo = z % 256;
  z_hi = z / 256;

  y = 81 + strlen( uc );
  y_lo = y % 256;
  y_hi = y / 256;

  x = 64 + strlen( uc );
  x_lo = x % 256;
  x_hi = x / 256;

  if( strlen( reply ) < 18 ) return NULL;
  magic1 = raw_string( ord( reply[16] ), ord( reply[17] ) );

  req = raw_string( 0x00, 0x00, len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18 );
  # 0x25 the SMB_COM_TRANSACTION command.

  if( ntlmssp_flag ) {
    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;
    if( isSignActive ) {
      req += raw_string( 0x07, 0x80 );
    } else {
      req += raw_string( 0x03, 0x80 );
    }
  } else {
    req += raw_string( 0x03, 0x80 );
  }

  req += magic1 + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00,tid_low, tid_high );

  if( ntlmssp_flag ) {
    req+= raw_string( 0x33, 0x0c );
  } else {
    req+= raw_string( 0x00, 0x28 );
  }

  req += raw_string( uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo,
                     x_hi, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x54, 0x00, x_lo, x_hi, 0x54, 0x00, 0x02,
                     0x00, 0x26, 0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00,
                     0x5C, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                     0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9,
                     0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                     x_lo, x_hi, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                     z_lo, z_hi, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00 );
    # 0x05 0x00 0x00 0x03 is the start of the DCE/RPC before that is the SMBv1 header and the command
    # Opnum is 0x0F = 15 so we call BaseRegOpenKey
    # [MS-RRP 3.1.5.15]

  if( strlen( reply ) < 85 ) return NULL;

  magic = raw_string( ord(reply[84] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 84 + i ) ) {
      magic += raw_string( ord( reply[84+i] ) );
    }
  }

  x = strlen( key ) + strlen( key ) + 2;
  x_lo = x % 256;
  x_hi = x / 256;

  req += magic + raw_string( x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC, 0xFD, 0x7F,
                             0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             key_len_lo, key_len_hi, 0x00, 0x00 ) + uc;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( ntlmssp_flag ) {
    if( isSignActive ) {
      len = strlen( req );
      seq_number += 1;
      packet = req;
      req = get_signature( key:s_sign_key, buf:packet, buflen:len, seq_number:seq_number );
      if( isnull( req ) ) return NULL;
    }
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 10 ) return NULL;

  if( ntlmssp_flag ) {
    multiplex_id += 1;
    if( isSignActive ) {
      # verify signature
      seq_number += 1;
      len = strlen( r );
      server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
      if( isnull( server_resp ) || ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
        return NULL;
      }

      orig_sign = substr( r, 18, 23 );
      serv_sign = substr( server_resp, 18, 23 );
      if( orig_sign != serv_sign ) {
        return NULL;
      }
    }
  }
  # -> END TODO

  len = ord( r[2] ) * 256;
  len = len + ord( r[3] );
  if( len < 100 ) return NULL;

  # pull the last 4 bytes off the end
  _na_start = ( strlen( r ) - 4 );
  for( _na_cnt = 0; _na_cnt < 4; _na_cnt++ ) {
    _na_data = _na_data + r[_na_start + _na_cnt];
  }

  # access denied, returned by Windows XP+
  if( _na_data == raw_string( 0x05, 0x00, 0x00, 0x00 )||
      _na_data == raw_string( 0x02, 0x00, 0x00, 0x00 ) ) {
    return NULL;
  }

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief internal function for SMBv2 similar to @ref registry1_get_key which shouldn't be called directly,
#        please see @ref registry_get_key for a description.
# @param soc   The socket used for the connection.
# @param uid   The session id.
# @param tid   The id of the tree.
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param key   The specific key to open, e.g. "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
# @param reply The reply after a registry key was opened. E.g. @ref registry_open_hklm
# @param write Could be used to write to a key, but the value is never set.
# @return Returns NULL if a failure occurs and FALSE it the NT_STATUS does not match.
#         On a successful response the response is returned.
function registry2_get_key( soc, uid, tid, pipe, key, reply, write ) {

  # isSignActive, ntlmssp_flag, seq_number, sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, key, reply, write;
  local_var key_len, key_len_hi, key_len_lo, uc, access_mask, req, data;
  local_var ioctl_req, dcerpc_req1, dcerpc_req2, magic, i, x, x_lo, x_hi;
  local_var rrs_req, len_rrs, len_rrs_lo, len_rrs_hi, dcerpc_req;
  local_var req_l, len_lo, len_hi, r, status, status2, r_head;
  local_var orig_sign, server_resp, serv_sign, len;
  local_var _na_start, _na_cnt, _na_data;

  if( isnull( soc ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_get_key" );
    return NULL;
  }

  if( isnull( uid ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_get_key" );
    return NULL;
  }

  if( isnull( tid ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_get_key" );
    return NULL;
  }

  if( isnull( pipe ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_get_key" );
    return NULL;
  }

  if( isnull( key ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry2_get_key" );
    return NULL;
  }

  if( isnull( reply ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry2_get_key" );
    return NULL;
  }

  key_len = strlen( key ) + 1;
  key_len_hi = key_len / 256;
  key_len_lo = key_len % 256;

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  uc = unicode( data:key );

  if( write ) {
    access_mask = raw_string( 0x19, 0x00, 0x02, 0x02 );
  } else {
    access_mask = raw_string( 0x19, 0x00, 0x02, 0x00 );
  }

  uc += access_mask;

  if( strlen( reply ) < 17 ) return NULL;

  # SMB2 Header
  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );

  # Ioctl Req FSCTL_PIPE_TRANSCEIVE
  ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                          pipe, 0x78, 0x00, 0x00, 0x00 );

  # Distributed Computing Environment / Remote Procedure Calls
  dcerpc_req1 = raw_string( 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00 );
  dcerpc_req2 = raw_string( 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x0f, 0x00 );

  #0x0f specifies BaseRegOpenKey as in [MS-RRP 3.1.5.15]

  if( strlen( reply ) < 141 ) return NULL;

  magic = raw_string( ord( reply[140] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 140 + i ) ) {
      magic += raw_string( ord( reply[140+i] ) );
    }
  }

  x = strlen( key ) + strlen( key ) + 2;
  x_lo = x % 256;
  x_hi = x / 256;

  # Remote Registry Service Req
  rrs_req = magic + raw_string( x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC, 0xFD, 0x7F,
                                0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                key_len_lo, key_len_hi, 0x00, 0x00 ) + uc;

  len_rrs = strlen( rrs_req ) + strlen( dcerpc_req1 ) + strlen( dcerpc_req2 ) + 2;
  len_rrs_lo = len_rrs % 256;
  len_rrs_hi = len_rrs / 256;

  dcerpc_req = dcerpc_req1 + raw_string( len_rrs_lo, len_rrs_hi ) + dcerpc_req2;

  ioctl_req += raw_string( len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00 );

  req += ioctl_req + dcerpc_req + rrs_req;
  req_l = strlen( req );
  len_lo = req_l % 256;
  len_hi = req_l / 256;

  if( isSignActive ) {
    if( smbv3 ) {
        sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
        sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_get_key: buf or key passed to signature function empty / too short" );
      return NULL;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return NULL;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv(socket:soc);
    if( strlen( r ) < 14 ) return NULL;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  if( ntlmssp_flag ) {
    multiplex_id += 1;
    if( isSignActive ) {
      # verify signature
      seq_number += 1;
      r_head = substr( r, 0, 3 );
      r = substr( r, 4, strlen( r ) - 1 );
      if( strlen( r ) < 64 ) return NULL;

      orig_sign = substr( r, 48, 63 );
      if( smbv3 ) {
        server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
      } else if( smbv2 ) {
        server_resp = get_smb2_signature( buf:r, key:sign_key );
      }
      if( isnull( server_resp ) || strlen( server_resp ) < 64 ) return NULL;

      serv_sign = substr( server_resp, 48, 63 );

      if( orig_sign != serv_sign ) {
        return FALSE;
      } else {
        r = r_head + r;
      }
    }
  }
  # END TODO ->

  len = ord( r[2] ) * 256;
  len = len + ord( r[3] );
  if( len < 100 ) return NULL;

  # pull the last 4 bytes off the end
  _na_start = ( strlen( r ) - 4 );
  for( _na_cnt = 0; _na_cnt < 4; _na_cnt++ ) {
    _na_data += r[_na_start + _na_cnt];
  }

  # access denied, returned by Windows XP+
  if( _na_data == raw_string( 0x05, 0x00, 0x00, 0x00 )||
      _na_data == raw_string( 0x02, 0x00, 0x00, 0x00 ) ) {
    return NULL;
  }

  ## 8 + BIOS-4bytes
  if( ord( r[12] ) == 0 ) {
    return r;
  } else {
   return FALSE;
  }
}

# @brief Checks if a specified key exists in the remote registry.
#
# @param key         The registry key to check, e.g. "SOFTWARE\Microsoft\Office"
# @param type        The type of the registry tree to query. Valid values are "HKLM, HKU and HKCU". If no type was specified the function
#                    defaults to "HKLM".
# @param query_cache Specifies if the existence of the key should be queried from the internal redis KB.
# @param save_cache  Specifies if the existence of the key should be cached into the internal redis KB.
#
# @return NULL if important connection parameters are missing or a connection couldn't be established,
#         TRUE if the key exist and FALSE otherwise.
#
function registry_key_exists( key, type, query_cache, save_cache ) {

  local_var key, type, query_cache, save_cache;
  local_var name, _smb_port, login, pass, domain, soc, r, prot, uid, tid, pipe, r2, i;
  local_var kb_proxy_key, kb_proxy;

  if( ! key ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry_key_exists" );
    return NULL;
  }

  if( isnull( query_cache ) )
    query_cache = TRUE;
  if( isnull( save_cache ) )
    save_cache = TRUE;

  if( ! type )
    type = "HKLM";
  else
    type = toupper( type );

  kb_proxy_key = "SMB//registry_key_exists//Registry//" + type + "//" + tolower( key );

  if( query_cache ) {
    kb_proxy = get_kb_item( kb_proxy_key );
    if( ! isnull( kb_proxy ) )
      return int( kb_proxy );
  }

  if( kb_smb_is_samba() ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#Windows SMB VT was started against a Samba Server" );
    return NULL;
  }

  name = kb_smb_name();
  if( ! name )
    return NULL;

  _smb_port = kb_smb_transport();
  if( ! _smb_port )
    return NULL;

  if( ! get_port_state( _smb_port ) )
    return NULL;

  soc = open_sock_tcp( _smb_port );
  if( ! soc )
    return NULL;

  login = kb_smb_login();
  if( ! login )
    login = "";

  pass = kb_smb_password();
  if( ! pass )
    pass = "";

  domain = kb_smb_domain();

  info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:pass, domain:domain, share:"IPC$" );

  if( isnull( info ) ) {
    close( soc );
    return NULL;
  }

  uid = info["uid"];
  tid = info["tid"];

  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  pipe = smbntcreatex_extract_pipe( reply:r );
  if( ! pipe ) {
    close( soc );
    return NULL;
  }

  r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  if( type == "HKLM" ) {
    r = registry_open_hklm( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKU" ) {
    r = registry_open_hku( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKCU" ) {
    r = registry_open_hkcu( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKCR" ) {
    r = registry_open_hkcr( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else {
    close( soc );
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry_key_exists: Unsupported '" + type + "' passed to type function parameter." );
    return NULL;
  }

  if( ! r ) {
    close( soc );
    return NULL;
  }

  r2 = registry_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r );
  if( ! isnull( r2 ) )
    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2 );
  registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );

  close( soc );
  if( ! r2 && strlen( r2 ) < 104 ) {
    # Using string() as set_kb_item won't allow to set a value of 0 into the KB.
    # It will be converted to an int again when querying the KB above.
    if( save_cache )
      replace_kb_item( name:kb_proxy_key, value:string( "0" ) );
    return FALSE;
  }

  if( strlen( uid ) == 8 ) {
    for( i = 1; i < 20; i++ ) {
      if( strlen( r2 ) > ( 140 + i ) ) {
        if( ord( r2[140+i] ) != 0 ) {
          if( save_cache )
            replace_kb_item( name:kb_proxy_key, value:TRUE );
          return TRUE;
        }
      }
    }
  } else {
    for( i = 1; i < 20; i++ ) {
      if( strlen( r2 ) > ( 84 + i ) ) {
        if( ord( r2[84+i] ) != 0 ) {
          if( save_cache )
            replace_kb_item( name:kb_proxy_key, value:TRUE );
          return TRUE;
        }
      }
    }
  }
  # Using string() as set_kb_item won't allow to set a value of 0 into the KB.
  # It will be converted to an int again when querying the KB above.
  if( save_cache )
    replace_kb_item( name:kb_proxy_key, value:string( "0" ) );
  return FALSE;
}

# @brief Accepts data and encodes it in a special unicode format for the use in Remote Registry Service.
# @note Get an item of type reg_sz from the key <-- Previous comment
# @param data The data that should be encoded.
# @return Returns a string in unicode.
function unicode2( data ) {

  local_var data, len, ret, i;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#unicode2" );

  len = strlen(data);
  ret = raw_string(0, ord(data[0]));

  for( i = 1; i < len; i++ ) {
    ret += raw_string(0, ord(data[i]));
  }

  if( len & 1 ) {
    ret += raw_string(0x00, 0x00);
  } else {
    ret += raw_string(0x00, 0x00, 0x00, 0x63);
  }
  return ret;
}

# @brief Decides if the SMBv1 or SMBv2 header should be used to retrieve data from a registry key.
# @param soc   The socket used for the connection.
# @param uid   The session id.
# @param tid   The id of the tree.
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param item  The item within the specified key to query, e.g. "Start"
# @param reply The return from @ref registry_get_key
# @return Return FALSE in case a failure occurs else return the received answer.
function registry_get_item_sz( soc, uid, tid, pipe, item, reply ) {

  local_var soc, uid, tid, pipe, item, reply, res;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_get_item_sz" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_get_item_sz" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_get_item_sz" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_get_item_sz" );
  if( isnull( item ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry_get_item_sz" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry_get_item_sz" );

  if( strlen( uid ) == 8 ) {
    res = registry2_get_item_sz( soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:reply );
    return res;
  } else {
    res = registry1_get_item_sz( soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:reply );
    return res;
  }
}

# @brief Uses the SMBv1 header to retrieve the data that is associated with the named value of a specified registry key.
# @param soc   The socket used for the connection.
# @param uid   The session id.
# @param tid   The id of the tree
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param item  The item within the specified key to query, e.g. "Start"
# @param reply The return from @ref registry_get_key
# @return Return FALSE in case a failure occurs else return the received answer.
function registry1_get_item_sz( soc, uid, tid, pipe, item, reply ) {

  # isSignActive, ntlmssp_flag, seq_number, s_sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, item, reply;
  local_var item_len, item_len_lo, item_len_hi, uc2, len, len_lo, len_hi;
  local_var tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var bcc, bcc_lo, bcc_hi, y, y_lo, y_hi, z, z_lo, z_hi, req;
  local_var magic, i, x, x_lo, x_hi, packet, r, server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry1_get_item_sz" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry1_get_item_sz" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry1_get_item_sz" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry1_get_item_sz" );
  if( isnull( item ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry1_get_item_sz" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry1_get_item_sz" );

  item_len = strlen( item ) + 1;
  item_len_lo = item_len % 256;
  item_len_hi = item_len / 256;

  uc2 = unicode2( data:item );
  len = 188 + strlen( uc2 );
  len_lo = len % 256;
  len_hi = len / 256;
  tid_low = tid % 256;
  tid_high = tid / 256;
  uid_low = uid % 256;
  uid_high = uid / 256;
  pipe_low = pipe % 256;
  pipe_high = pipe / 256;

  bcc = 121 + strlen( uc2 );
  bcc_lo = bcc % 256;
  bcc_hi = bcc / 256;

  y = 80 + strlen( uc2 );
  y_lo = y % 256;
  y_hi = y / 256;

  z = 104 + strlen( uc2 );
  z_lo = z % 256;
  z_hi = z / 256;

  req = raw_string( 0x00, 0x00, len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18 );
  #0x25 is the SMB_COM_TRANSACTION command

  if( ntlmssp_flag ) {
    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;
    if( isSignActive ) {
     req += raw_string( 0x07, 0x80 );
    } else {
     req += raw_string( 0x03, 0x80 );
    }
  } else {
    req += raw_string( 0x03, 0x80 );
  }

  req += raw_string( 0x1D, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_low, tid_high );

  if( ntlmssp_flag ) {
    req += raw_string( 0x33, 0x0c );
  } else {
    req += raw_string( 0x00, 0x28 );
  }

  req += raw_string( uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, z_lo,
                     z_hi, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x54, 0x00, z_lo, z_hi, 0x54, 0x00, 0x02,
                     0x00, 0x26, 0x00, pipe_low, pipe_high, bcc_lo, bcc_hi, 0x00,
                     0x5C, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                     0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x5C,
                     0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                     z_lo, z_hi, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                     y_lo, y_hi, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00 );
  # 0x05 0x00 0x00 0x03 is the start of the DCE/RPC everything before is header and the command

  if( strlen( reply ) < 104 ) return FALSE;

  # The received handle.
  magic = raw_string( ord( reply[84] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 84 + i ) ) {
      magic += raw_string( ord( reply[84+i] ) );
    }
  }

  x = 2 + strlen( item ) + strlen( item );
  x_lo = x % 256;
  x_hi = x / 256;

  y = y + 3;
  y_lo = y % 256;
  y_hi = y / 256;

  req += magic + raw_string( x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC, 0xFD, 0x7F,
                             0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             item_len_lo, item_len_hi, 0x00 ) + uc2 +
                 raw_string( 0x00, 0x34, 0xFF, 0x12, 0x00, 0xEF, 0x10, 0x40,
                             0x00, 0x18, 0x1E, 0x7c, 0x00, 0x00, 0x04, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x3C, 0xFF, 0x12, 0x00, 0x00, 0x04, 0x00,
                             0x00, 0x30, 0xFF, 0x12, 0x00, 0x00, 0x00, 0x00,
                             0x00 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( ntlmssp_flag ) {
    if( isSignActive ) {
      len = strlen( req );
      seq_number += 1;
      packet = req;
      req = get_signature( key:s_sign_key, buf:packet, buflen:len, seq_number:seq_number );
      if( isnull( req ) ) return FALSE;
    }
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );

  if( ntlmssp_flag ) {
    multiplex_id += 1;
    if( r && isSignActive ) {
      # verify signature
      seq_number += 1;
      len = strlen( r );
      server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
      if( isnull( server_resp ) ) return FALSE;
      if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
        return FALSE;
      }

      orig_sign = substr( r, 18, 23 );
      serv_sign = substr( server_resp, 18, 23 );
      if( orig_sign != serv_sign ) {
        return FALSE;
      }
    }
  }
  # -> END TODO

  return r;
}

# @brief Uses the SMBv2 header to retrieve the data that is associated with the named value of a specified registry key.
# @param soc   The socket used for the connection.
# @param uid   The session id.
# @param tid   The id of the tree
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe.
# @param item  The item within the specified key to query, e.g. "Start"
# @param reply The return from @ref registry_get_key
# @return Return FALSE in case a failure occurs else return the received answer.
function registry2_get_item_sz( soc, uid, tid, pipe, item, reply ) {

  # isSignActive, ntlmssp_flag, seq_number, sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, item, reply;
  local_var item_len, item_len_lo, item_len_hi, uc2, len, len_lo, len_hi, data;
  local_var bcc, bcc_lo, bcc_hi, y, y_lo, y_hi, z, z_lo, z_hi, req;
  local_var ioctl_req, dcerpc_req, dcerpc_req1, dcerpc_req2, req_l;
  local_var magic, i, x, x_lo, x_hi, rrs_req, len_rrs, len_rrs_lo, len_rrs_hi;
  local_var sig, r, status, status2, r_head, orig_sign, server_resp, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_get_item_sz" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_get_item_sz" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_get_item_sz" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_get_item_sz" );
  if( isnull( item ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry2_get_item_sz" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry2_get_item_sz" );

  item_len = strlen( item ) + 1;
  item_len_lo = item_len % 256;
  item_len_hi = item_len / 256;
  uc2 = unicode2( data:item );

  len = 188 + strlen( uc2 );
  len_lo = len % 256;
  len_hi = len / 256;

  bcc = 121 + strlen( uc2 );
  bcc_lo = bcc % 256;
  bcc_hi = bcc / 256;

  y = 80 + strlen( uc2 );
  y_lo = y % 256;
  y_hi = y / 256;

  z = 104 + strlen( uc2 );
  z_lo = z % 256;
  z_hi = z / 256;

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  # SMB2 Header
  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );

  if( ntlmssp_flag ) {
    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;
  }

  # Ioctl Req FSCTL_PIPE_TRANSCEIVE
  ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                          pipe, 0x78, 0x00, 0x00, 0x00 );

  # Distributed Computing Environment / Remote Procedure Calls
  # dcerpc_req = raw_string( 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
  #                          0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  #                          0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00 );

  dcerpc_req1 = raw_string( 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00 );
  dcerpc_req2 = raw_string( 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x11, 0x00 );
  # 0x11 0x00 is the Opnum 17 --> BaseRegQueryValue
  # [MS-RPP 3.1.5.17]

  if( strlen( reply ) < 141 ) return FALSE ;

  # The received handle.
  magic = raw_string( ord( reply[140] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 140 + i ) ) {
      magic += raw_string( ord( reply[140+i] ) );
    }
  }

  x = strlen( item ) + strlen( item ) + 2;
  x_lo = x % 256;
  x_hi = x / 256;

  # Remote Registry Service Req
  rrs_req = magic + raw_string( x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC, 0xFD, 0x7F,
                                0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                item_len_lo, item_len_hi, 0x00 ) + uc2
                  + raw_string( 0x00, 0x34, 0xFF, 0x12, 0x00, 0xEF, 0x10, 0x40,
                                0x00, 0x18, 0x1E, 0x7c, 0x00, 0x00, 0x04, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x3C, 0xFF, 0x12, 0x00, 0x00, 0x04, 0x00,
                                0x00, 0x30, 0xFF, 0x12, 0x00, 0x00, 0x00, 0x00,
                                0x00 );

  len_rrs = strlen( rrs_req ) + strlen( dcerpc_req1 ) + strlen( dcerpc_req2 ) + 2;
  len_rrs_lo = len_rrs % 256;
  len_rrs_hi = len_rrs / 256;

  dcerpc_req = dcerpc_req1 + raw_string( len_rrs_lo, len_rrs_hi ) + dcerpc_req2;

  ioctl_req += raw_string( len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00 );

  req = req + ioctl_req + dcerpc_req + rrs_req;
  req_l = strlen( req );
  len_lo = req_l % 256;
  len_hi = req_l / 256;

  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_get_item_sz: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return FALSE;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv( socket:soc );
    if( strlen( r ) < 14 ) return FALSE;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  if( ntlmssp_flag ) {
    multiplex_id += 1;
    if( isSignActive ) {
      # verify signature
      seq_number += 1;

      r_head = substr( r, 0, 3 );
      r = substr( r, 4, strlen( r ) - 1 );
      if( strlen( r ) < 64 ) return FALSE;

      orig_sign = substr( r, 48, 63 );
      if( smbv3 ) {
        server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
      } else if( smbv2 ) {
        server_resp = get_smb2_signature( buf:r, key:sign_key );
      }
      if( isnull( server_resp ) ) return FALSE;
      if( strlen( server_resp ) < 64 ) return FALSE;
      serv_sign = substr( server_resp, 48, 63 );

      if( orig_sign != serv_sign ) {
        return FALSE;
      } else {
        r = r_head + r;
      }
    }
  }
  # END TODO ->

  return r;
}

# @brief Extracts binary data from the received answer from a key value access, when the SMBv2 header is used.
# @param data The received values from @ref registry_get_item_sz
# @return NULL in case a error occurred else the accessed value is returned.
function registry1_decode_binary( data ) {

  local_var data, len, data_offset, data_len, index, o, i;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry1_decode_binary" );

  if( strlen( data ) < 53 ) return NULL;

  len = ord(data[2])*256;
  len = len + ord(data[3]);
  if( len < 130 ) return NULL;

  data_offset = ord( data[52] ) * 256;
  data_offset = data_offset + ord( data[51] ) + 4;
  if( strlen( data ) < ( data_offset + 45 ) ) {
    return NULL;
  }

  data_len = ord( data[data_offset+43] );
  data_len = data_len * 256;
  data_len = data_len + ord( data[data_offset+44] );
  index = data_offset + 48;

  o = "";
  for( i = 0; i < data_len; i++ ) {
    if( strlen( data ) > ( index + i ) ) {
      o = string( o, raw_string( ord( data[index+i] ) ) );
    }
  }
  return o;
}

# @brief Extracts binary data from the received answer from a key value access, when the SMBv2 header is used.
# @param data The received values from @ref registry_get_item_sz
# @return NULL in case a error occurred else the accessed value is returned.
function registry2_decode_binary( data ) {

  local_var data, len, data_offset, data_len, index, o, i;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry2_decode_binary" );

  if( strlen( data ) < 102 ) return NULL;

  len = ord( data[2] ) * 256;
  len = len + ord( data[3] );
  if( len < 181 ) return NULL;

  data_offset = ord( data[101] ) * 256;
  data_offset = data_offset + ord( data[100] ) + 4;
  if( strlen( data ) < ( data_offset + 48 ) ) {
    return NULL;
  }

  data_len = ord( data[data_offset+47] );
  data_len = data_len * 256 + ord( data[data_offset+46] );
  data_len = data_len * 256 + ord( data[data_offset+45] );
  data_len = data_len * 256 + ord( data[data_offset+44] );
  index = data_offset + 48;
  o = "";

  for( i = 0; i < data_len; i++ ) {
    if( strlen( data ) > ( index + i ) ) {
      o = string( o, raw_string( ord( data[index+i] ) ) );
    }
  }
  return o;
}


# @brief Depending on the received answer it is decided if we need to extract binary data from a SMBv1 or SMBv2 header.
# @note Decode the reply from the registry <-- Previous comment
# @param data The received values from @ref registry_get_item_sz
# @param uid The session id.
# @return NULL in case a error occurred else the accessed value is returned.
function registry_decode_binary( data, uid ) {

  local_var data, uid, res;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry_decode_binary" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_decode_binary" );

  if( strlen( uid ) == 8 ) {
    res = registry2_decode_binary( data:data );
    return res;
  } else {
    res = registry1_decode_binary( data:data );
    return res;
  }
}

# @brief Depending on the received answer it is decided if we need to extract data of the type SZ from a SMBv1 or SMBv2 header.
# @note Decode the reply from the registry <-- Previous comment
# @param data The received values from @ref registry_get_item_sz
# @param uid The session id.
# @return NULL in case a error occurred else the accessed value is returned.
function registry_decode_sz( data, uid ) {

  local_var data, uid, res;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry_decode_sz" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_decode_sz" );

  if( strlen( uid ) == 8 ) {
    res = registry2_decode_sz( data:data );
    return res;
  } else {
    res = registry1_decode_sz( data:data );
    return res;
  }
}

# @brief Extracts data of the type SZ from the received answer from a key value access, when the SMBv1 header is used.
# @param data The received values from @ref registry_get_item_sz
# @return NULL in case a error occurred else the accessed value is returned.
function registry1_decode_sz( data ) {

  local_var data, len, data_offset, data_len, index, o, i;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry1_decode_sz" );

  if( strlen( data ) < 53 ) return NULL;

  len = ord( data[2] ) * 256;
  len = len + ord( data[3] );
  if( len < 128 ) return NULL;

  data_offset = ord( data[52] ) * 256;
  data_offset = data_offset + ord( data[51] ) + 4;
  if( strlen( data ) < ( data_offset + 48 ) ) {
    return NULL;
  }

  data_len = ord( data[data_offset+47] );
  data_len = data_len * 256 + ord( data[data_offset+46] );
  data_len = data_len * 256 + ord( data[data_offset+45] );
  data_len = data_len * 256 + ord( data[data_offset+44] );
  index = data_offset + 48;
  o = "";
  data_len = data_len - 2;

  for( i = 0; i < data_len; i = i + 2 ) {
    if( strlen( data ) > ( index + i ) ) {
      o = string( o, raw_string( ord( data[index+i] ) ) );
    }
  }
  return o;
}

# @brief Extracts data of the type SZ from the received answer from a key value access, when the SMBv2 header is used.
# @param data The received values from @ref registry_get_item_sz
# @return NULL in case a error occurred else the accessed value is returned.
function registry2_decode_sz( data ) {

  local_var data, len, data_offset, data_len, index, o, i;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry2_decode_sz" );

  if( strlen( data ) < 102 ) return NULL;

  len = ord( data[2] ) * 256;
  len = len + ord( data[3] );
  if( len < 128 ) return NULL;

  data_offset = ord( data[101] ) * 256;
  data_offset = data_offset + ord( data[100] ) + 4;
  if( strlen( data ) < ( data_offset + 48 ) ) return NULL;

  data_len = ord( data[data_offset+47] );
  data_len = data_len * 256 + ord( data[data_offset+46] );
  data_len = data_len * 256 + ord( data[data_offset+45] );
  data_len = data_len * 256 + ord( data[data_offset+44] );
  index = data_offset + 48;
  o = "";
  data_len = data_len - 2;

  for( i = 0; i < data_len; i = i + 2 ) {
    if( strlen( data ) > ( index + i ) ) {
      o = string( o, raw_string( ord( data[index+i] ) ) );
    }
  }
  return o;
 }

# @brief Decides if a SMBv1 or SMBv2 header should be used to access the data of a registry key.
# @note Get an item of type reg_dword from the key <-- Previous comment
#       Is there any difference to @ref registry_get_item_sz
# @param soc   The socket used for the connection
# @param uid   The session id.
# @param tid   The id of the tree.
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe
# @param item  The item within the specified key to query, e.g. "Start"
# @param reply The result of @ref registry_get_key.
# @return Returns the received answer or FALSE/NULL in case of a failure
function registry_get_item_dword( soc, uid, tid, pipe, item, reply ) {

  local_var soc, uid, tid, pipe, item, reply, res;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry_get_item_dword" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry_get_item_dword" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry_get_item_dword" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry_get_item_dword" );
  if( isnull( item ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry_get_item_dword" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry_get_item_dword" );

  if( strlen( uid ) == 8 ) {
    res = registry2_get_item_dword( soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:reply );
    return res;
  } else {
    res = registry1_get_item_dword( soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:reply );
    return res;
  }
}

# @brief Uses the SMBv1 header to retrieve the data that is associated with the named value of a specified registry key.
# @param soc   The socket used for the connection
# @param uid   The session id.
# @param tid   The id of the tree.
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe
# @param item  The item within the specified key to query, e.g. "Start"
# @param reply The result of @ref registry_get_key.
# @return Returns the received answer or FALSE/NULL in case of a failure
function registry1_get_item_dword( soc, uid, tid, pipe, item, reply ) {

  # isSignActive, ntlmssp_flag, seq_number, s_sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, item, reply;
  local_var item_len, item_len_lo, item_len_hi, uc2, len, len_lo, len_hi, tid_low, tid_high, uid_low, uid_high;
  local_var pipe_low, pipe_high, bcc, bcc_lo, bcc_hi, y, y_lo, y_hi, z, z_lo, z_hi, req, i;
  local_var magic, x, x_lo, x_hi, packet, server_resp, orig_sign, serv_sign, r;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry1_get_item_dword" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry1_get_item_dword" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry1_get_item_dword" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry1_get_item_dword" );
  if( isnull( item ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry1_get_item_dword" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry1_get_item_dword" );

  item_len = strlen( item ) + 1;
  item_len_lo = item_len % 256;
  item_len_hi = item_len / 256;

  uc2 = unicode2( data:item );
  len = 188 + strlen( uc2 );
  len_lo = len % 256;
  len_hi = len / 256;

  tid_low = tid % 256;
  tid_high = tid / 256;
  uid_low = uid % 256;
  uid_high = uid / 256;
  pipe_low = pipe % 256;
  pipe_high = pipe / 256;

  bcc = 121 + strlen( uc2 );
  bcc_lo = bcc % 256;
  bcc_hi = bcc / 256;

  y = 80 + strlen( uc2 );
  y_lo = y % 256;
  y_hi = y / 256;

  z = 104 + strlen( uc2 );
  z_lo = z % 256;
  z_hi = z / 256;

  req = raw_string( 0x00, 0x00, len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18 );

  if( ntlmssp_flag ) {
    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;
    if( isSignActive ) {
      req += raw_string( 0x07, 0x80 );
    } else {
      req += raw_string( 0x03, 0x80 );
    }
  } else {
    req += raw_string( 0x03, 0x80 );
  }

  req += raw_string( 0x1D, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_low, tid_high );

  if( ntlmssp_flag ) {
    req += raw_string( 0x33, 0x0c );
  } else {
    req += raw_string( 0x00, 0x28 );
  }

  req += raw_string( uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, z_lo,
                     z_hi, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x54, 0x00, z_lo, z_hi, 0x54, 0x00, 0x02,
                     0x00, 0x26, 0x00, pipe_low, pipe_high, bcc_lo, bcc_hi, 0x00,
                     0x5C, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                     0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x5C,
                     0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                     z_lo, z_hi, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                     y_lo, y_hi, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00 );

  if( strlen( reply) < 85 ) return FALSE;

  magic = raw_string( ord( reply[84] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 84 + i ) ) {
      magic += raw_string( ord( reply[84+i] ) );
    }
  }

  x = 2 + strlen( item ) + strlen( item );
  x_lo = x % 256;
  x_hi = x / 256;

  y = y + 3;
  y_lo = y % 256;
  y_hi = y / 256;

  req += magic + raw_string( x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC, 0xFD, 0x7F,
                             0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             item_len_lo, item_len_hi, 0x00 )
               + uc2
               + raw_string( 0x00, 0x34, 0xFF, 0x12, 0x00, 0xEF, 0x10, 0x40,
                             0x00, 0x18, 0x1E, 0x7c, 0x00, 0x00, 0x04, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x3C, 0xFF, 0x12, 0x00, 0x00, 0x04, 0x00,
                             0x00, 0x30, 0xFF, 0x12, 0x00, 0x00, 0x00, 0x00,
                             0x00 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( ntlmssp_flag && isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number ); # TBD: This overwrites the req declared previously
    if( isnull( req ) ) return FALSE;
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );

  if( ntlmssp_flag ) {
    multiplex_id += 1;
    if( r && isSignActive ) {
      # verify signature
      seq_number += 1;
      len = strlen( r );
      server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
      if( isnull( server_resp ) ) return FALSE;
      if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
        return FALSE;
      }

      orig_sign = substr( r, 18, 23 );
      serv_sign = substr( server_resp, 18, 23 );
      if( orig_sign != serv_sign ) {
        return FALSE;
      }
    }
  }
  # -> END TODO

  return r;
}

# @brief Uses the SMBv2 header to retrieve the data that is associated with the named value of a specified registry key.
# @param soc   The socket used for the connection
# @param uid   The session id.
# @param tid   The id of the tree.
# @param pipe  The id of the pipe. See @ref smbntcreatex_extract_pipe
# @param item  The item within the specified key to query, e.g. "Start"
# @param reply The result of @ref registry_get_key.
# @return Returns the received answer or FALSE/NULL in case of a failure
function registry2_get_item_dword( soc, uid, tid, pipe, item, reply ) {

  # isSignActive, ntlmssp_flag, seq_number, sign_key, g_mlo, g_mhi and multiplex_id are global_vars!!!

  local_var soc, uid, tid, pipe, item, reply;
  local_var item_len, item_len_lo, item_len_hi, uc2, req, ioctl_req, dcerpc_req1, dcerpc_req2, magic, i;
  local_var x, x_hi, x_lo, len_rrs, len_rrs_lo, len_rrs_hi, req_l, len_lo, len_hi, sig, r;
  local_var status, status2, r_head, orig_sign, server_resp, serv_sign, data;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#registry2_get_item_dword" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#registry2_get_item_dword" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#registry2_get_item_dword" );
  if( isnull( pipe ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pipe#-#registry2_get_item_dword" );
  if( isnull( item ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry2_get_item_dword" );
  if( isnull( reply ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#reply#-#registry2_get_item_dword" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;
  item_len = strlen( item ) + 1;
  item_len_lo = item_len % 256;
  item_len_hi = item_len / 256;
  uc2 = unicode2( data:item );

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00 );
  # 0x0b SMB_IOCTL

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );

  # Ioctl Req FSCTL_PIPE_TRANSCEIVE
  ioctl_req = raw_string( 0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                          pipe, 0x78, 0x00, 0x00, 0x00 );

  # Distributed Computing Environment / Remote Procedure Calls
  dcerpc_req1 = raw_string( 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00 );
  dcerpc_req2 = raw_string( 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x11, 0x00 );
  #0x11 is a BaseRegQueryValue from [MS-RRP 3.1.5.17]

  if( strlen( reply ) < 141 ) return FALSE;

  # The received handle
  magic = raw_string( ord( reply[140] ) );
  for( i = 1; i < 20; i++ ) {
    if( strlen( reply ) > ( 140 + i ) ) {
      magic += raw_string( ord( reply[140+i] ) );
    }
  }

  x = 2 + strlen( item ) + strlen( item );
  x_lo = x % 256;
  x_hi = x / 256;

  # Remote Registry Service Req
  rrs_req =  magic + raw_string( x_lo, x_hi, 0x0A, 0x02, 0x00, 0xEC, 0xFD, 0x7F,
                                 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 item_len_lo, item_len_hi, 0x00 )
                   + uc2
                   + raw_string( 0x00, 0x34, 0xFF, 0x12, 0x00, 0xEF, 0x10, 0x40,
                                 0x00, 0x18, 0x1E, 0x7c, 0x00, 0x00, 0x04, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x3C, 0xFF, 0x12, 0x00, 0x00, 0x04, 0x00,
                                 0x00, 0x30, 0xFF, 0x12, 0x00, 0x00, 0x00, 0x00,
                                 0x00 );

  len_rrs = strlen( rrs_req ) + strlen( dcerpc_req1 ) + strlen( dcerpc_req2 ) + 2;
  len_rrs_lo = len_rrs % 256;
  len_rrs_hi = len_rrs / 256;

  dcerpc_req = dcerpc_req1 + raw_string( len_rrs_lo, len_rrs_hi ) + dcerpc_req2;

  ioctl_req += raw_string( len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00 );

  req += ioctl_req + dcerpc_req + rrs_req;
  req_l = strlen( req );
  len_lo = req_l % 256;
  len_hi = req_l / 256;

  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_get_item_dword: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return NULL;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv(socket:soc);
    if( strlen( r ) < 14 ) return NULL;

    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  if( strlen( r ) < 80 ) return FALSE;

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;

    r_head = substr( r, 0, 3 );
    r = substr(r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr(r, 48, 63);
    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }
  }
  # END TODO ->

  return r;
}

# @brief Decides if a SMBv1 or SMBv2 header was used and decodes the dword data based on this information.
# @note Decode the reply from the registry <-- Previous comment
# @param data The received answer from @ref registry_get_item_dword.
# @return Return NULL in case of a failure else return the decoded data.
function registry_decode_dword( data ) {

  local_var data, value;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry_decode_dword" );

  if( ord( data[4] ) == 254 ) {
    value = registry2_decode_dword( data:data );
    return value;
  } else {
    value = registry1_decode_dword( data:data );
    return value;
  }
}

# @brief Decodes the data of the type dword from the answer that used a SMBv1 header.
# @param data The received answer from @ref registry_get_item_dword.
# @return Return NULL in case of a failure else return the decoded data.
function registry1_decode_dword( data ) {

  local_var data, len, data_offset, data_len, index, o, i, t;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry1_decode_dword" );

  if( strlen( data ) < 53 ) return NULL;

  len = ord( data[2] ) * 256;
  len = len + ord( data[3] );
  if( len < 126 ) return NULL;

  data_offset = ord( data[52] ) * 256;
  data_offset = data_offset + ord( data[51] ) + 4;

  if( strlen( data ) < ( data_offset + 45 ) ) return NULL;

  data_len = ord( data[data_offset+43] );
  data_len = data_len * 256;
  data_len = data_len + ord( data[data_offset+44] );
  index = data_offset + 48;
  o = "";

  for( i = data_len; i > 0; i = i - 1 ) {
    t *= 256;
    if( strlen( data ) > ( index + i - 1 ) ) {
      t += ord( data[index+i-1] );
    }
  }
  return t;
}

# @brief Decodes the data of the type dword from the answer that used a SMBv2 header.
# @param data The received answer from @ref registry_get_item_dword.
# @return Return NULL in case of a failure else return the decoded data.
function registry2_decode_dword( data ) {

  local_var data, len, data_offset, data_len, index, o, i, t;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#registry2_decode_dword" );

  if( strlen( data ) < 104 ) return NULL;

  len = ord( data[2] ) * 256;
  len = len + ord( data[3] );
  if( len < 126 ) return NULL;

  data_offset = ord( data[103] ) * 256;
  data_offset = data_offset + ord( data[102] ) * 256;
  data_offset = data_offset + ord( data[101] ) * 256;
  data_offset = data_offset + ord( data[100] ) + 4;

  if( strlen( data ) < ( data_offset + 45 ) ) return NULL;

  data_len = ord( data[data_offset+43] );
  data_len = data_len * 256;
  data_len = data_len + ord( data[data_offset+44] );
  index = data_offset + 48;
  o = "";

  for( i = data_len; i > 0; i = i - 1 ) {
    t *= 256;
    if( strlen( data ) > ( index + i - 1 ) ) {
      t += ord( data[index+i-1] );
    }
  }
  return t;
}

# @brief Get the DWORD value of a specified key and item from the remote registry. The function queries the knowledge base first
#        to check if an item was already found and cached and if not it tries to establish a SMB connection to the remote host.
#
# @param key  The registry key to query, e.g. "SYSTEM\CurrentControlSet\Services\mrxsmb10"
# @param item The item within the specified key to query, e.g. "Start"
# @param type The type of the registry tree to query. Valid values are "HKLM, HKU and HKCU". If no type was specified the function
#             defaults to "HKLM".
#
# @return NULL if important connection parameters are missing, a connection couldn't be established or
#         if the key or item could not be found (no FALSE because a DWORD could be 0) and the value
#         of the queried item within the specified key otherwise.
#
function registry_get_dword( key, item, type ) {

  local_var key, item, type;
  local_var kb_proxy_key, kb_proxy, name, _smb_port, login, pass, domain, soc;
  local_var r, prot, uid, tid, pipe, r2, r3, r3_value;

  if( isnull( key ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry_get_dword" );
    return NULL;
  }

  if( isnull( item ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry_get_dword" );
    return NULL;
  }

  if( ! type )
    type = "HKLM";
  else
    type = toupper( type );

  # Query KB ("proxy") first.
  kb_proxy_key = "SMB//registry_get_dword//Registry//" + type + "//" + tolower( key ) + "//" + tolower( item );
  kb_proxy = get_kb_item( kb_proxy_key );
  if( ! isnull( kb_proxy )|| kb_proxy )
    return kb_proxy;

  if( kb_smb_is_samba() ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#Windows SMB VT was started against a Samba Server" );
    return NULL;
  }

  name = kb_smb_name();
  if( ! name ) return NULL;

  _smb_port = kb_smb_transport();
  if( ! _smb_port ) return NULL;
  if( ! get_port_state( _smb_port ) ) return NULL;
  soc = open_sock_tcp( _smb_port );
  if( ! soc ) return NULL;

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();
  if( ! login ) login = "";
  if( ! pass )  pass = "";

  info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:pass, domain:domain, share:"IPC$" );

  if( isnull( info ) ) {
    close( soc );
    return NULL;
  }

  uid = info["uid"];
  tid = info["tid"];

  # Create a pipe to \winreg
  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  # and extract its ID
  pipe = smbntcreatex_extract_pipe( reply:r );
  if( ! pipe ) {
    close( soc );
    return NULL;
  }

  # Setup things
  r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  if( type == "HKLM" ) {
    r = registry_open_hklm( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKU" ) {
    r = registry_open_hku( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKCU" ) {
    r = registry_open_hkcu( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else {
    close( soc );
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry_get_dword: Unsupported '" + type + "' passed to type function parameter." );
    return NULL;
  }

  if( ! r ) {
    close( soc );
    return NULL;
  }

  r2 = registry_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r );
  if( r2 ) {

    r3 = registry_get_item_dword( soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:r2 );

    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2 );
    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );

    if( r3 )
      r3_value = registry_decode_dword( data:r3 );

    close( soc );

    # Place value into the KB
    if( ! isnull( r3_value ) ) {
      # Using string() as set_kb_item won't allow to set a return value of 0
      set_kb_item( name:kb_proxy_key, value:string( r3_value ) );
    }
    return r3_value;
  }

  if( ! isnull( r2 ) )
    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2 );
  registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );
  close( soc );
  return NULL;
}

# @brief Get the BIN value of a specified key and item from the remote registry.
#
# @param key  The registry key to query, e.g. "SYSTEM\CurrentControlSet\Services\mrxsmb10"
# @param item The item within the specified key to query, e.g. "Start"
# @param type The type of the registry tree to query. Valid values are "HKLM, HKU and HKCU". If no type was specified the function
#             defaults to "HKLM".
#
# @return NULL if important connection parameters are missing or a connection couldn't be established,
#         FALSE if the key or item could not be found and the value of the queried item within the specified key otherwise.
#
function registry_get_binary( key, item, type ) {

  local_var key, item, type;
  local_var name, _smb_port, login, pass, domain, soc, r, prot, uid, tid, pipe;
  local_var r2, r3, r3_value;

  if( isnull( key ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry_get_binary" );
    return NULL;
  }

  if( isnull( item ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry_get_binary" );
    return NULL;
  }

  if( kb_smb_is_samba() ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#Windows SMB VT was started against a Samba Server" );
    return NULL;
  }

  if( ! type )
    type = "HKLM";
  else
    type = toupper( type );

  name = kb_smb_name();
  if( ! name ) return NULL;

  _smb_port = kb_smb_transport();
  if( ! _smb_port ) return NULL;
  if( ! get_port_state( _smb_port ) ) return NULL;
  soc = open_sock_tcp( _smb_port );
  if( ! soc ) return NULL;

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();
  if( ! login ) login = "";
  if( ! pass )  pass = "";

  info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:pass, domain:domain, share:"IPC$" );

  if( isnull( info ) ) {
    close( soc );
    return NULL;
  }

  uid = info["uid"];
  tid = info["tid"];

  # Create a pipe to \winreg
  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  # and extract its ID
  pipe = smbntcreatex_extract_pipe( reply:r );
  if( ! pipe ) {
    close( soc );
    return NULL;
  }

  # Setup things
  r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  if( type == "HKLM" ) {
    r = registry_open_hklm( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKU" ) {
    r = registry_open_hku( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKCU" ) {
    r = registry_open_hkcu( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else {
    close( soc );
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry_get_binary: Unsupported '" + type + "' passed to type function parameter." );
    return NULL;
  }

  if( ! r ) {
    close( soc );
    return NULL;
  }

  r2 = registry_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r );
  if( r2 ) {

    r3 = registry_get_item_sz( soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:r2 );

    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2 );
    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );

    r3_value = registry_decode_binary( data:r3, uid:uid );
    close( soc );

    return r3_value;
  }

  if( ! isnull( r2 ) )
    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2 );
  registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );
  close( soc );
  return FALSE;
}

# @brief Get the SZ value of a specified key and item from the remote registry. The function queries the knowledge base first
#        to check if an item was already found and cached and if not it tries to establish a SMB connection to the remote host.
#
# @param key         The registry key to query, e.g. "SYSTEM\CurrentControlSet\Services\mrxsmb10"
# @param item        The item within the specified key to query, e.g. "Start"
# @param type        The type of the registry tree to query. Valid values are "HKLM, HKU and HKCU". If no type was specified the function
#                    defaults to "HKLM".
# @param multi_sz    If the value is a multi_sz, newlines should be considered.
# @param query_cache Specifies if the returned item should be queried from the internal redis KB.
# @param save_cache  Specifies if the returned item should be cached into the internal redis KB.
#
# @return NULL if important connection parameters are missing or a connection couldn't be established,
#         FALSE if the key or item could not be found and the value of the queried item within the specified key otherwise.
#
function registry_get_sz( key, item, type, multi_sz, query_cache, save_cache ) {

  local_var key, item, type, multi_sz, query_cache, save_cache;
  local_var kb_proxy_key, kb_proxy, name, _smb_port, login, pass, domain, soc;
  local_var r, prot, uid, tid, pipe, r2, r3, r3_value;

  if( isnull( key ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#registry_get_sz" );
    return NULL;
  }

  if( isnull( item ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#registry_get_sz" );
    return NULL;
  }

  if( isnull( query_cache ) )
    query_cache = TRUE;
  if( isnull( save_cache ) )
    save_cache = TRUE;

  if( ! type )
    type = "HKLM";
  else
    type = toupper( type );

  kb_proxy_key = "SMB//registry_get_sz//Registry//" + type + "//" + tolower( key ) + "//" + tolower( item );

  if( query_cache ) {
    kb_proxy = get_kb_item( kb_proxy_key );
    if( ! isnull( kb_proxy ) || kb_proxy )
      return kb_proxy;
  }

  if( kb_smb_is_samba() ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#Windows SMB VT was started against a Samba Server" );
    return NULL;
  }

  name = kb_smb_name();
  if( ! name )
    return NULL;

  _smb_port = kb_smb_transport();
  if( ! _smb_port )
    return NULL;

  if( ! get_port_state( _smb_port ) )
    return NULL;

  soc = open_sock_tcp( _smb_port );
  if( ! soc )
    return NULL;


  login = kb_smb_login();
  if( ! login )
    login = "";

  pass = kb_smb_password();
  if( ! pass )
    pass = "";

  domain = kb_smb_domain();

  info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:pass, domain:domain, share:"IPC$" );

  if( isnull( info ) ) {
    close( soc );
    return NULL;
  }

  uid = info["uid"];
  tid = info["tid"];

  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  pipe = smbntcreatex_extract_pipe( reply:r );
  if( ! pipe ) {
    close( soc );
    return NULL;
  }

  r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! r ) {
    close( soc );
    return NULL;
  }

  if( type == "HKLM" ) {
    r = registry_open_hklm( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKU" ) {
    r = registry_open_hku( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else if( type == "HKCU" ) {
    r = registry_open_hkcu( soc:soc, uid:uid, tid:tid, pipe:pipe );
  } else {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry_get_sz: Unsupported '" + type + "' passed to type function parameter." );
    close( soc );
    return NULL;
  }

  if( ! r ) {
    close( soc );
    return NULL;
  }

  r2 = registry_get_key( soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r );
  if( r2 ) {

    r3 =  registry_get_item_sz( soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:r2 );

    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2 );
    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );

    if( r3 )
      r3_value = registry_decode_sz( data:r3, uid:uid );

    close( soc );

    if( multi_sz ) {
      # item is MULTI_SZ, which are multiple lines. Could not find another way to replace the "newline" char.
      for( i = 0; i < strlen( r3_value ) - 1; i++ ) {
        if( hexstr( r3_value[i]) == '00' )
          val += '\n';
        else
          val += r3_value[i];
      }
      if( ! val )
        val = "";

      if( save_cache )
        replace_kb_item( name:kb_proxy_key, value:val );
      return val;
    }

    if( ! isnull( r3_value ) ) {
      r3_value = chomp( r3_value ); # Sometimes we're getting a trailing newline back so make sure that this is removed.
      if( save_cache )
        replace_kb_item( name:kb_proxy_key, value:r3_value );
    } else {
      r3_value = FALSE;
    }
    return r3_value;
  }

  if( ! isnull( r2 ) )
    registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2 );
  registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r );
  close( soc );
  return FALSE;
}

# @brief Creates or opens a file with the SMB header
# @note # Open file <file> <-- Previous comment
# @param socket The socket used for the connection.
# @param uid The session id of the current session.
# @param tid The id of the tree connect.
# @param file The name of a file (with its complete path?).
# @return In case something fails NULL or FALSE is returned. If everything goes right the fileid is returned.
function OpenAndX_NTLMSSP( socket, uid, tid, file ) {

  # isSignActive, seq_number, s_sign_key, multiplex_id, g_mhi and g_mlo are global_vars!!!

  local_var socket, uid, tid, file;
  local_var len_lo, len_hi, tid_lo, tid_hi, uid_lo, uid_hi, bcc_lo, bcc_hi, req, len;
  local_var packet, rep, server_resp, orig_sign, serv_sign, fid_lo, fid_hi;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#OpenAndX_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#OpenAndX_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#OpenAndX_NTLMSSP" );
  if( isnull( file ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#OpenAndX_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  len_lo = ( 66 + strlen( file ) ) % 256;
  len_hi = ( 66 + strlen( file ) ) / 256;

  tid_lo = tid % 256;
  tid_hi = tid / 256;

  uid_lo = uid % 256;
  uid_hi = uid / 256;

  bcc_lo = strlen( file ) % 256;
  bcc_hi = strlen( file ) / 256;
  req = raw_string( 0x00, 0x00, len_hi, len_lo,   0xFF, 0x53,
                    0x4D, 0x42, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x08 );
  # 0x2D SMB_COM_OPEN_ANDX --> Extended file open with AndX chaining

  if( isSignActive ) {
    req += raw_string( 0x05, 0x40 );
  } else {
    req += raw_string( 0x01, 0x40 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x33, 0x0c,
                     uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, 0xFF, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x40, 0x00, 0x06, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, bcc_lo, bcc_hi )
       + file
       + raw_string( 0x00 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
    if( isnull( req ) ) return FALSE;
  }

  send( socket:socket, data:req );
  rep = smb_recv( socket:socket );

  multiplex_id += 1;
  if( rep && isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( rep );
    server_resp = get_signature( key:s_sign_key, buf:rep, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( rep, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( strlen( rep ) < 43 ) {
    return NULL;
  } else {
    fid_lo = ord( rep[41] );
    fid_hi = ord( rep[42] );
    return( fid_lo + ( fid_hi * 256 ) );
  }
}

# @brief Creates or opens a file with the SMBv2 header
# @param socket The socket used for the connection.
# @param uid The session id of the current session.
# @param tid The id of the tree connect.
# @param file The name of a file (with its complete path?).
# @return In case something fails NULL or FALSE is returned. If everything goes right the result of @ref smbntcreatex_extract_pipe is returned.
function OpenAndX2_NTLMSSP( socket, uid, tid, file ) {

  # isSignActive, seq_number, sign_key, multiplex_id, g_mhi and g_mlo are global_vars!!!

  local_var socket, uid, tid, file;
  local_var file_le, file_len, bcc_lo, bcc_hi, uc, req, namelen, name_hi, name_lo, sig, r, data;
  local_var status, status2, r_head, orig_sign, server_resp, serv_sign, len, len_hi, len_lo;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#OpenAndX2_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#OpenAndX2_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#OpenAndX2_NTLMSSP" );
  if( isnull( file ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#OpenAndX2_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;
  file_le = strlen( file ) + 1;
  file = substr( file, 1, file_le );

  file_len = strlen( file ) + strlen( file );

  bcc_lo = file_len % 256;
  bcc_hi = file_len / 256;
  # Filename
  uc = unicode( data:file );

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x60, 0x1f );
  # The 0x05 0x00 is the SMBv2 command for create/open in the header [MS-SMB2]

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid );

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  req += raw_string( 0x39, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x78, 0x00, bcc_lo, bcc_hi,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 )
       + uc;

  #length of entire packet
  len = strlen( req );
  len_hi = len / 256;
  len_lo = len % 256;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#OpenAndX2_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  send( socket:socket, data:data );
  r = smb_recv( socket:socket );
  if( strlen( r ) < 14 ) return NULL;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv( socket:socket );
    if( strlen( r ) < 14 ) return NULL;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  if( strlen( r ) < 10 ) return FALSE;

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;
    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr( r, 48, 63 );
    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }
  }
  # -> END TODO

  if( strlen( r ) < 65 ) {
    return NULL;
  } else {
    return( smbntcreatex_extract_pipe( reply:r ) );
  }
}

# @brief Decides if the file should be opened/created with SMBv1 or SMBv2 header.
# @param socket The socket used for the connection.
# @param uid The session id of the current session.
# @param tid The id of the tree connect.
# @param file The name of a file (with its complete path?).
# @return In case something fails NULL or FALSE is returned. Otherwise the response of the called functions or the file id is returned.
function OpenAndX( socket, uid, tid, file ) {

  # ntmlssp_flag is global_var!!!

  local_var socket, uid, tid, file, response;
  local_var len_lo, len_hi, tid_lo, tid_hi, uid_lo, uid_hi, bcc_lo, bcc_hi, req;
  local_var rep, fid_lo, fid_hi;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#OpenAndX" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#OpenAndX" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#OpenAndX" );
  if( isnull( file ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#OpenAndX" );

  if( ntlmssp_flag ) {
    if( strlen( uid ) == 8 ) {
      response = OpenAndX2_NTLMSSP( socket:socket, uid:uid, tid:tid, file:file );
      return response;
    } else {
      response = OpenAndX_NTLMSSP( socket:socket, uid:uid, tid:tid, file:file );
      return response;
    }
  } else {

    len_lo = ( 66 + strlen( file ) ) % 256;
    len_hi = ( 66 + strlen( file ) ) / 256;

    tid_lo = tid % 256;
    tid_hi = tid / 256;

    uid_lo = uid % 256;
    uid_hi = uid / 256;

    bcc_lo = strlen( file ) % 256;
    bcc_hi = strlen( file ) / 256;

    # Just a shorter process of the SMBv1 variant because we do not need any checks for signing if NTLMSSP is not enabled.
    req = raw_string( 0x00, 0x00, len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42,
                      0x2D, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28,
                      uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, 0xFF, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x40, 0x00, 0x06, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, bcc_lo, bcc_hi )
        + file
        + raw_string( 0x00 );

    send( socket:socket, data:req );
    rep = smb_recv( socket:socket );
    if( strlen( rep ) < 43 ) {
      return NULL;
    } else {
      fid_lo = ord( rep[41] );
      fid_hi = ord( rep[42] );
      return( fid_lo + ( fid_hi * 256 ) );
    }
  }
}

# @brief Uses the SMBv2 header with NTLMSSP capabilities to read from a file.
# @note Read <count> bytes at offset <off> <-- Previous comment.
# @param socket The socket used for the connection.
# @param uid The session id of the current session.
# @param tid The id of the tree connect.
# @param fid The id of the file.
# @param count How many bytes should be read.
# @param off Offset to begin the file read.
# @return Returns FALSE or NULL if something fails otherwise the file content that was read is returned.
function ReadAndX2_NTLMSSP( socket, uid, tid, fid, count, off ) {

  # isSignActive, g_mhi, g_mlo, multiplex_id, seq_number and sign_key are global_vars!!!

  local_var socket, uid, tid, fid, count, off;
  local_var cnt_lo_lo, cnt_lo_hi, cnt_hi_lo, cnt_hi_hi;
  local_var off_lo_lo, off_lo_lo_lo, off_lo_lo_hi, off_lo_hi, off_lo_hi_lo;
  local_var off_lo_hi_hi, off_hi_lo, off_hi_hi;
  local_var req, namelen, name_hi, name_lo, sig, r, status, status2;
  local_var r_head, orig_sign, server_resp, serv_sign;
  local_var len, len_hi, len_lo;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ReadAndX2_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#ReadAndX2_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#ReadAndX2_NTLMSSP" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#ReadAndX2_NTLMSSP" );
  if( isnull( count ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#count#-#ReadAndX2_NTLMSSP" );
  if( isnull( off ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#off#-#ReadAndX2_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;
  cnt_lo_lo = count % 256; count /= 256;
  cnt_lo_hi = count % 256; count /= 256;
  cnt_hi_lo = count % 256; count /= 256;
  cnt_hi_hi = count;

  off_lo_lo = off % 256;     off /= 256;
  off_lo_lo_lo = off % 256;  off /= 256;
  off_lo_lo_hi = off % 256;  off /= 256;
  off_lo_hi = off % 256;     off /= 256;
  off_lo_hi_lo = off % 256;  off /= 256;
  off_lo_hi_hi = off % 256;  off /= 256;
  off_hi_lo = off % 256;     off /= 256;
  off_hi_hi = off;

  # 0x08 0x00 SMB2_READ command as specified in [MS-SMB 2.2.1.2]
  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x60, 0x1f );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid );

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  # SMB2 READ Request starts here [MS-SMB2 2.2.19]
  req += raw_string( 0x31, 0x00, 0x50, 0x00, cnt_lo_lo, cnt_lo_hi, cnt_hi_lo, cnt_hi_hi,
                     off_lo_lo, off_lo_lo_lo, off_lo_lo_hi, off_lo_hi,
                     off_lo_hi_lo, off_lo_hi_hi, off_hi_lo, off_hi_hi,
                     fid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  len = strlen( req );
  len_hi = len / 256;
  len_lo = len % 256;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#ReadAndX2_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else{
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }
  send( socket:socket, data:data );
  r = smb_recv( socket:socket );
  if( strlen( r ) < 14 ) return NULL;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv( socket:socket );
    if( strlen( r ) < 14 ) return NULL;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  multiplex_id += 1;
  if( isSignActive ) {
    # verify signature
    seq_number += 1;
    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr( r, 48, 63 );
    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }
  }
  # -> END TODO

  if( strlen( r ) < 85 ) return FALSE;
  return( substr( r, 84, strlen( r ) - 1 ) );
}

# @brief Uses the SMBv1 header with NTLMSSP capabilities to read from a file.
# @param socket The socket used for the connection.
# @param uid The session id of the current session.
# @param tid The id of the tree connect.
# @param fid The id of the file.
# @param count How many bytes should be read.
# @param off Offset to begin the file read.
# @return Returns FALSE or NULL if something fails otherwise the file content that was read is returned.
function ReadAndX1_NTLMSSP( socket, uid, tid, fid, count, off ) {

  # isSignActive, seq_number, s_sign_key, multiplex_id, g_mhi and g_mlo are global_vars!!!

  local_var socket, uid, tid, fid, count, off;
  local_var uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, cnt_lo, cnt_hi;
  local_var off_lo_lo, off_lo_hi, off_hi_lo, off_hi_hi, req, len, packet, r;
  local_var server_resp, orig_sign, serv_sign;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ReadAndX1_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#ReadAndX1_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#ReadAndX1_NTLMSSP" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#ReadAndX1_NTLMSSP" );
  if( isnull( count ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#count#-#ReadAndX1_NTLMSSP" );
  if( isnull( off ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#off#-#ReadAndX1_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  uid_lo = uid % 256; uid_hi = uid / 256;
  tid_lo = tid % 256; tid_hi = tid / 256;
  fid_lo = fid % 256; fid_hi = fid / 256;
  cnt_lo = count % 256; cnt_hi = count / 256;

  off_lo_lo = off % 256;  off /= 256;
  off_lo_hi = off % 256;  off /= 256;
  off_hi_lo = off % 256;  off /= 256;
  off_hi_hi = off;

  req = raw_string( 0x00, 0x00, 0x00, 0x37, 0xFF, 0x53, 0x4D, 0x42,
                    0x2E, 0x00, 0x00, 0x00, 0x00, 0x08 );

  if( isSignActive ) {
    req += raw_string( 0x05, 0x40 );
  } else {
    req += raw_string( 0x01, 0x40 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x33, 0x0c,
                     uid_lo, uid_hi, g_mlo, g_mhi, 0x0A, 0xFF, 0x00, 0x00,
                     0x00, fid_lo, fid_hi, off_lo_lo, off_lo_hi, off_hi_lo, off_hi_hi, cnt_lo,
                     cnt_hi, cnt_lo, cnt_hi, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
    if( isnull( req ) ) return FALSE;
  }

  send( socket:socket, data:req );
  r = smb_recv( socket:socket );

  multiplex_id += 1;
  if( r && isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( strlen( r ) < 37 + 28 ) return NULL;
  return( substr( r, 36 + 28, strlen( r ) - 1 ) );
}

# @brief Decides if the file should be read with SMBv1 or SMBv2 header.
# @param socket The socket used for the connection.
# @param uid The session id of the current session.
# @param tid The id of the tree connect.
# @param fid The id of the file.
# @param count How many bytes should be read.
# @param off Offset to begin the file read.
# @return In case something fails NULL or FALSE is returned. Otherwise the content of the file is returned.
function ReadAndX( socket, uid, tid, fid, count, off ) {

  local_var socket, uid, tid, fid, count, off, response;
  local_var uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, cnt_lo, cnt_hi;
  local_var off_lo_lo, off_lo_hi, off_hi_lo, off_hi_hi, req, r;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ReadAndX" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#ReadAndX" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#ReadAndX" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#ReadAndX" );
  if( isnull( count ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#count#-#ReadAndX" );
  if( isnull( off ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#off#-#ReadAndX" );

  if( ntlmssp_flag ) {
    if( strlen( uid ) == 8 ) {
      response = ReadAndX2_NTLMSSP( socket:socket, uid:uid, tid:tid, fid:fid, count:count, off:off );
      return response;
    } else {
      response = ReadAndX1_NTLMSSP( socket:socket, uid:uid, tid:tid, fid:fid, count:count, off:off );
      return response;
    }
  } else {

    # Just a shorter process of the SMBv1 variant because we do not need any checks for signing if NTLMSSP is not enabled.
    uid_lo = uid % 256; uid_hi = uid / 256;
    tid_lo = tid % 256; tid_hi = tid / 256;
    fid_lo = fid % 256; fid_hi = fid / 256;
    cnt_lo = count % 256; cnt_hi = count / 256;

    off_lo_lo = off % 256;  off /= 256;
    off_lo_hi = off % 256;  off /= 256;
    off_hi_lo = off % 256;  off /= 256;
    off_hi_hi = off;

    req = raw_string( 0x00, 0x00, 0x00, 0x37, 0xFF, 0x53, 0x4D, 0x42,
                      0x2E, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28,
                      uid_lo, uid_hi, g_mlo, g_mhi, 0x0A, 0xFF, 0x00, 0x00,
                      0x00, fid_lo, fid_hi, off_lo_lo, off_lo_hi, off_hi_lo, off_hi_hi, cnt_lo,
                      cnt_hi, cnt_lo, cnt_hi, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00 );

    send( socket:socket, data:req );
    r = smb_recv( socket:socket );

    if( strlen( r ) < 37 + 28 ) return NULL;
    return( substr( r, 36 + 28, strlen( r ) - 1 ) );
  }
}

# @brief Decides which method for closing a file should be used.
# @param soc The socket used for the connection.
# @param uid The sessionid of the used session.
# @param tid The ID of the tree connect.
# @param fid The return from @ref OpenAndX which should be a file id.
# @return Returns FALSE or NULL in case of a failure. When everything is successful the server response is returned.
function smb_close_request( soc, uid, tid, fid ) {

  local_var soc, uid, tid, fid, ret;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb_close_request" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb_close_request" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb_close_request" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#smb_close_request" );

  if( strlen( uid ) == 8 ) {
    ret = smb2_close_request( soc:soc, uid:uid, tid:tid, fid:fid );
    return ret;
  } else {
    ret = smb1_close_request( soc:soc, uid:uid, tid:tid, fid:fid );
    return ret;
  }
}

# @brief Closes a file with the SMBv2 header.
# @param soc The socket used for the connection.
# @param uid The sessionid of the used session.
# @param tid The ID of the tree connect.
# @param fid The return from @ref OpenAndX which should be a file id.
# @return Returns FALSE when the signature fails or the status is incorrect, NULL when the receive fails and the server response on success.
function smb2_close_request( soc, uid, tid, fid ) {

  # isSignActive, g_mhi, g_mlo, multiplex_id, seq_number and sign_key are global_vars!!!

  local_var soc, uid, tid, fid;
  local_var req, close_req, sig, r, status, status2, data;
  local_var len, len_hi, len_lo;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb2_close_request" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb2_close_request" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb2_close_request" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#smb2_close_request" );

  g_mhi = multiplex_id / 256;
  g_mhi = multiplex_id % 256;

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x60, 0x1f );

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );

  close_req = raw_string( 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, fid );

  req += close_req;

  len = strlen( req );
  len_hi = len / 256;
  len_lo = len % 256;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#smb2_close_request: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }

  send( socket:soc, data:data );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 14 ) return NULL;

  ##If status is pending, wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv( socket:soc );
    status = ord( r[12] );
    status2 = ord( r[13] );
  }
  # -> END TODO

  if( ord( r[11] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Closes a file with the SMBv1 header.
# @param soc The socket used for the connection.
# @param uid The sessionid of the used session.
# @param tid The ID of the tree connect.
# @param fid The return from @ref OpenAndX which should be a file id.
# @return Returns FALSE when the signature fails or the status is incorrect, NULL when the receive fails and the server response on success.
function smb1_close_request( soc, uid, tid, fid ) {

  # isSignActive, seq_number, s_sign_key, multiplex_id, g_mhi and g_mlo are global_vars!!!

  local_var soc, uid, tid, fid;
  local_var uid_lo, uid_hi, tid_lo, tid_hi, fid_hi, fid_lo, req;
  local_var len, packet, server_resp, orig_sign, serv_sign;

  if( isnull( soc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#smb1_close_request" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb1_close_request" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb1_close_request" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#smb1_close_request" );

  uid_lo = uid % 256; uid_hi = uid / 256;
  tid_lo = tid % 256; tid_hi = tid / 256;
  fid_lo = fid % 256; fid_hi = fid / 256;

  req = raw_string( 0x00, 0x00, 0x00, 0x29, 0xFF, 0x53, 0x4D, 0x42,
                    0x04, 0x00, 0x00, 0x00, 0x00, 0x08 );

  if( ntlmssp_flag ) {
    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;
    if( isSignActive ) {
      req += raw_string( 0x05, 0xc8 );
    } else {
      req += raw_string( 0x01, 0xc8 );
    }
  } else {
    req += raw_string( 0x01, 0xc8 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi );

  if( ntlmssp_flag ) {
    req += raw_string( 0x33, 0x0c );
  } else {
    req += raw_string( 0x00, 0x28 );
  }

  req += raw_string( uid_lo, uid_hi, g_mlo, g_mhi, 0x03, fid_lo, fid_hi, 0xff,
                     0xff, 0xff, 0xff, 0x00, 0x00 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
    if( isnull( req ) ) return FALSE;
  }

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 24 ) return NULL;

  if( ntlmssp_flag ) {
    multiplex_id += 1;
    if( r && isSignActive ) {
      # verify signature
      seq_number += 1;
      len = strlen( r );
      server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
      if( isnull( server_resp ) ) return FALSE;
      if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
        return FALSE;
      }

      orig_sign = substr( r, 18, 23 );
      serv_sign = substr( server_resp, 18, 23 );
      if( orig_sign != serv_sign ) {
        return FALSE;
      }
    }
  }
  # -> END TODO

  if( ord( r[9] ) == 0 ) {
    return r;
  } else {
    return FALSE;
  }
}

# @brief Gathers information about the size of a file using the SMBv2 header.
# @note Returns the size of the file pointed by <fid> <-- Previous comment
# @param socket The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree connect.
# @param fid The id of the file.
# @return Returns NULL or FALSE in case of a failure. If everything goes alright the size of the file is returned.
function smb2_get_file_size_NTLMSSP( socket, uid, tid, fid ) {

  # isSignActive, g_mhi, g_mlo, multiplex_id, seq_number and sign_key are global_vars!!!

  local_var socket, uid, tid, fid;
  local_var req, get_info, req_l, len_lo, len_hi, sig, r, status, status2, data;
  local_var r_head, orig_sign, server_resp, serv_sign, ret;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smb2_get_file_size_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb2_get_file_size_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb2_get_file_size_NTLMSSP" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#smb2_get_file_size_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  req = raw_string( 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x6f, 0x00 );
  # 0x10 0x00 is a SMB2 QUERY_INFO command [MS-SMB2]

  if( isSignActive ) {
    req += raw_string( 0x08, 0x00, 0x00, 0x00 );
  } else {
    req += raw_string( 0x00, 0x00, 0x00, 0x00 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     tid, uid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00 );
  # SMB header should be finished at this point

  # SMB2 QUERY_INFO Request
  get_info = raw_string( 0x29, 0x00, 0x01, 0x05, 0x04, 0x11, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         fid );
  req += get_info;
  req_l = strlen( req );
  len_lo = req_l % 256;
  len_hi = req_l / 256;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    if( smbv3 ) {
      sig = smb_cmac_aes_signature( buf:req, key:sign_key );
    } else if ( smbv2 ) {
      sig = get_smb2_signature( buf:req, key:sign_key );
    }
    if( isnull( sig ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#smb2_get_file_size_NTLMSSP: buf or key passed to signature function empty / too short" );
      return FALSE;
    }
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + sig;
  } else {
    data = raw_string( 0x00, 0x00, len_hi, len_lo ) + req;
  }

  if( smbEncryption ) {
    data = create_smb2_transform_header_package( len_hi:len_hi, len_lo:len_lo, uid:uid, req:req );
  }

  send( socket:socket, data:data );
  r = smb_recv( socket:socket );
  if( strlen( r ) < 14 ) return NULL;

  ##if status is pending , wait for response
  status = ord( r[12] );
  status2 = ord( r[13] );
  while( status == 3 && status2 == 1 ) {
    ##PDU will arrive late
    r = smb_recv( socket:socket );
    if( strlen( r ) < 14 ) return NULL;
    status = ord( r[12] );
    status2 = ord( r[13] );
  }

  multiplex_id += 1;
  if( r && isSignActive ) {
    # verify signature
    seq_number += 1;
    r_head = substr( r, 0, 3 );
    r = substr( r, 4, strlen( r ) - 1 );
    if( strlen( r ) < 64 ) return FALSE;

    orig_sign = substr( r, 48, 63 );
    if( smbv3 ) {
      server_resp = smb_cmac_aes_signature( buf:r, key:sign_key );
    } else if( smbv2 ) {
      server_resp = get_smb2_signature( buf:r, key:sign_key );
    }
    if( isnull( server_resp ) ) return FALSE;
    if( strlen( server_resp ) < 64 ) return FALSE;

    serv_sign = substr( server_resp, 48, 63 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    } else {
      r = r_head + r;
    }
  }
  # -> END TODO

  if( strlen( r ) < 88 ) return NULL;
  ret = ord( r[87] );
  ret = ret * 256 + ord( r[86] );
  ret = ret * 256 + ord( r[85] );
  ret = ret * 256 + ord( r[84] );
  return ret;
}

# @brief Gathers information about the size of a file using the SMBv1 header.
# @param socket The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree connect.
# @param fid The id of the file.
# @return Returns NULL or FALSE in case of a failure. If everything goes alright the size of the file is returned.
function smb1_get_file_size_NTLMSSP( socket, uid, tid, fid ) {

  # isSignActive, seq_number, s_sign_key, multiplex_id, g_mhi and g_mlo are global_vars!!!

  local_var socket, uid, tid, fid;
  local_var uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, req;
  local_var len, r, packet, server_resp, orig_sign, serv_sign, ret;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smb1_get_file_size_NTLMSSP" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb1_get_file_size_NTLMSSP" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb1_get_file_size_NTLMSSP" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#smb1_get_file_size_NTLMSSP" );

  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  uid_lo = uid % 256; uid_hi = uid / 256;
  tid_lo = tid % 256; tid_hi = tid / 256;
  fid_lo = fid % 256; fid_hi = fid / 256;

  # 0x32 is the command for a SMB_COM_TRANSACTION2 [MS-CIFS Section 2.2.2.1]
  req = raw_string( 0x00, 0x00, 0x00, 0x48, 0xFF, 0x53, 0x4D, 0x42,
                    0x32, 0x00, 0x00, 0x00, 0x00, 0x08 );

  if( isSignActive ) {
    req += raw_string( 0x05, 0x40 );
  } else {
    req += raw_string( 0x01, 0x40 );
  }

  # Starting at 0x0F the following is specified in [MS-CIFS Section 2.2.4.46.1]
  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x33, 0x0c,
                     uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, 0x04, 0x00, 0x00,
                     0x00, 0x02, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                     0x00, 0x44, 0x00, 0x00, 0x00, 0x48, 0x00, 0x01,
                     0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x44, 0x20,
                     fid_lo, fid_hi, 0x07, 0x01 );

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
    if( isnull( req ) ) return FALSE;
  }

  send( socket:socket, data:req );
  r = smb_recv( socket:socket );
  if( strlen( r ) < 116 ) return FALSE;

  multiplex_id += 1;
  if( r && isSignActive ) {
    # verify signature
    seq_number += 1;
    len = strlen( r );
    server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
    if( isnull( server_resp ) ) return FALSE;
    if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
      return FALSE;
    }

    orig_sign = substr( r, 18, 23 );
    serv_sign = substr( server_resp, 18, 23 );
    if( orig_sign != serv_sign ) {
      return FALSE;
    }
  }
  # -> END TODO

  if( strlen( r ) < 116 ) return NULL;
  ret = ord( r[115] );
  ret = ret * 256 + ord( r[114] );
  ret = ret * 256 + ord( r[113] );
  ret = ret * 256 + ord( r[112] );
  return ret;
}

# @brief Decides if the SMBv2 or SMBv1 header with NTLMSSP is used or SMBv1 without NTLMSSP to get the size of a file.
# @param socket The socket used for the connection.
# @param uid The session id.
# @param tid The id of the tree connect.
# @param fid The id of the file.
# @return Returns NULL or FALSE in case of a failure. If everything goes alright the size of the file is returned.
function smb_get_file_size( socket, uid, tid, fid ) {

  # ntlmssp_flag is global_var!!!

  local_var socket, uid, tid, fid, response;
  local_var uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, req;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smb_get_file_size" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#smb_get_file_size" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#smb_get_file_size" );
  if( isnull( fid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#smb_get_file_size" );

  if( ntlmssp_flag ) {
    if( strlen( uid ) == 8 ) {
      response = smb2_get_file_size_NTLMSSP( socket:socket, uid:uid, tid:tid, fid:fid );
      return response;
    } else {
      response = smb1_get_file_size_NTLMSSP( socket:socket, uid:uid, tid:tid, fid:fid );
      return response;
    }
  } else {

    uid_lo = uid % 256; uid_hi = uid / 256;
    tid_lo = tid % 256; tid_hi = tid / 256;
    fid_lo = fid % 256; fid_hi = fid / 256;

    req = raw_string( 0x00, 0x00, 0x00, 0x48, 0xFF, 0x53, 0x4D, 0x42,
                      0x32, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28,
                      uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, 0x04, 0x00, 0x00,
                      0x00, 0x02, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                      0x00, 0x44, 0x00, 0x00, 0x00, 0x48, 0x00, 0x01,
                      0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x44, 0x20,
                      fid_lo, fid_hi, 0x07, 0x01 );

    send( socket:socket, data:req );
    r = smb_recv( socket:socket );
    if( strlen( r ) < 116 ) return -1;

    ret = ord( r[115] );
    ret = ret * 256 + ord( r[114] );
    ret = ret * 256 + ord( r[113] );
    ret = ret * 256 + ord( r[112] );
    return ret;
  }
}


# @brief Unclear but only usage is in secpod_ms11-020_remote.nasl for a specific SMB vulnerability
# @note Gives the listing in the pattern <pattern>
#       If pattern is set to NULL, then we return the content of the root (\*) <-- Previous comment
# @param socket  The socket used for the connection.
# @param uid     The session id.
# @param tid     The id of the tree.
# @param pattern
# @return ?
function FindFirst2( socket, uid, tid, pattern ) {

  # isSignActive, g_mhi, g_mlo, multiplex_id, seq_number and sign_key are global_vars!!!

  local_var socket, uid, tid, pattern;
  local_var i, unicode_pattern, ret, bcc, bcc2, len;
  local_var uid_lo, uid_hi, tid_lo, tid_hi, bcc_lo, bcc_hi;
  local_var bcc2_lo, bcc2_hi, len_lo, len_hi;
  local_var data_off, data_off_lo, data_off_hi, req;
  local_var packet, server_resp, orig_sign, serv_sign, r;
  local_var err, search_id, off, eof, t, nxt, name;

  if( isnull( socket ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#FindFirst2" );
  if( isnull( uid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#FindFirst2" );
  if( isnull( tid ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#FindFirst2" );

  if( isnull( pattern ) ) pattern = "\*";

  for( i = 0; i < strlen( pattern ); i++ ) {
    unicode_pattern += pattern[i] + raw_string(0);
  }

  unicode_pattern += raw_string(0, 0);
  ret = NULL;

  bcc = 15 + strlen( unicode_pattern );
  bcc2 = bcc - 3;
  len  = 80 + strlen( unicode_pattern );

  uid_lo = uid % 256; uid_hi = uid / 256;
  tid_lo = tid % 256; tid_hi = tid / 256;
  bcc_lo = bcc % 256; bcc_hi = bcc / 256;
  bcc2_lo = bcc2 % 256; bcc2_hi = bcc2 / 256;
  len_lo = len % 256; len_hi = len / 256;

  data_off = 80 + strlen( unicode_pattern );
  data_off_lo = data_off % 256; data_off_hi = data_off / 256;

  req = raw_string( 0x00, 0x00, len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42,
                    0x32, 0x00, 0x00, 0x00, 0x00, 0x08 );

  if( ntlmssp_flag && isSignActive ) {
    req += raw_string( 0x05, 0xC0 );
  } else {
    req += raw_string( 0x01, 0xC0 );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi );

  if( ntlmssp_flag ) {
    g_mhi = multiplex_id / 256;
    g_mlo = multiplex_id % 256;
    req += raw_string( 0x33, 0x0c );
  } else {
    req += raw_string( 0x00, 0x28 );
  }

  req += raw_string( uid_lo, uid_hi, g_mlo, g_mhi, 0x0F, bcc2_lo, bcc2_hi, 0x00,
                     0x00, 0x0A, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, bcc2_lo,
                     bcc2_hi, 0x44, 0x00, 0x00, 0x00, data_off_lo, data_off_hi, 0x01,
                     0x00, 0x01, 0x00, bcc_lo, bcc_hi, 0x00, 0x44, 0x20,
                     0x16, 0x00, 0x00, 0x02, 0x06, 0x00, 0x04, 0x01,
                     0x00, 0x00, 0x00, 0x00 )
       + unicode_pattern;

  # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
  if( ntlmssp_flag && isSignActive ) {
    len = strlen( req );
    seq_number += 1;
    packet = req;
    req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
    if( isnull( req ) ) return FALSE;
  }

  send( socket:socket, data:req );
  r = smb_recv( socket:socket );
  if( strlen( r ) < 80 ) return NULL;

  if( ntlmssp_flag ) {
    multiplex_id += 1;
    if( isSignActive ) {
      # verify signature
      seq_number += 1;
      len = strlen( r );
      server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
      if( isnull( server_resp ) ) return FALSE;
      if( ( strlen( server_resp ) < 24 ) || ( len < 24 ) ) {
        return FALSE;
      }

      orig_sign = substr( r, 18, 23 );
      serv_sign = substr( server_resp, 18, 23 );
      if( orig_sign != serv_sign ) {
        return FALSE;
      }
    }
  }
  # -> END TODO

  err = substr( r, 11, 12 );
  if( hexstr( err) != "0000" ) {
    return NULL;
  }

  search_id = substr( r, 60, 61 );
  off = 72;
  while( TRUE ) {
    eof = ord( r[64] );
    while( TRUE ) {
      t = 1;
      nxt = 0;

      if( off + i + 4 >= strlen( r ) ) {
        break;
      }

      for( i = 0; i < 4; i++ ) {
        nxt += ord(r[off+i]) * t;
        t *= 256;
      }

      t = 1;
      len = 0;

      if( off + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + i + 4 >= strlen( r ) ) {
        break;
      }

      for( i = 0; i < 4; i++ ) {
        len += ord(r[off+4+4+8+8+8+8+8+8+4+i]) * t;
        t *= 256;
      }

      if( len >= strlen( r ) ) {
        break;
      }

      name = NULL;

      if( off + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 1 + 1 + 24 + i + len > strlen( r ) ) {
        break;
      }

      for( i = 0; i < len; i += 2 ) {
        name += r[off+4+4+8+8+8+8+8+8+4+4+4+1+1+24+i];
      }

      if( ! isnull( name ) ) {
        if( isnull( ret ) ) {
          ret = make_list(name);
        } else {
          ret = make_list(ret, name);
        }
      }

      off += nxt;
      if( nxt == 0 ) break;

      if( ( off >= strlen( r ) )|| off < 0 ) {
        return ret;
      }
    }

    if( eof ) {
      break;
    } else {
      req = raw_string( 0x00, 0x00, 0x00, 0x52, 0xff, 0x53, 0x4d, 0x42,
                        0x32, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xC0,
                        0x00, 0x00, 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28,
                        uid_lo, uid_hi, g_mlo, g_mhi, 0x0f, 0x0e, 0x00, 0x00,
                        0x00, 0x0a, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
                        0x00, 0x44, 0x00, 0x00, 0x00, 0x52, 0x00, 0x01,
                        0x00, 0x02, 0x00, 0x11, 0x00, 0x00, 0x44, 0x20 )
          + search_id
          + raw_string( 0x00, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
                        0x0e, 0x00, 0x00, 0x00 );

      send( socket:socket, data:req );
      r = smb_recv( socket:socket );
      if( r && strlen( r ) > 12 ) {
        err = substr( r, 11, 12 );
      }

      if( hexstr( err ) != "0000" ) {
        return NULL;
      }

      if( strlen( r ) <= 64 && strlen( r ) > 12 && hexstr( substr( r, 9, 12 ) ) == "00000000" ) {
        r = smb_recv( socket:socket );
      } else if( strlen( r ) <= 64 ) {
        break;
      }
      off = 68;
    }
  }
  return ret;
}

# @brief Gets the system root of a 64bit System.
# @return Returns FALSE if the key does not exists or can not be accessed. If the key is present gets the content the SystemRoot item.
function smb_get_systemroot() {

  local_var sroot, key, item;

  if( sroot = get_kb_item( "SMB/SystemRoot" ) ) return sroot;

  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\";

  if( ! registry_key_exists( key:key ) ) {
    return FALSE;
  }

  item  = "SystemRoot";
  sroot = registry_get_sz( item:item, key:key );

  if( ! isnull( sroot ) ) {
    set_kb_item( name:"SMB/SystemRoot", value:sroot );
    return sroot;
  } else {
    return FALSE;
  }
}

# @brief Gets the system root of a 32bit System.
# @return Returns FALSE if the key does not exists or can not be accessed. If the key is present gets the content the SystemRoot item.
function smb_get_system32root() {

  local_var sroot, key, item;

  if( sroot = get_kb_item( "SMB/SystemRoot32" ) ) return sroot;

  key = "SOFTWARE\Microsoft\COM3\Setup\";

  item  = "Install Path";
  sroot = registry_get_sz( item:item, key:key );

  # Windows\system32 should not be a part of sroot
  if( "Windows\system32" >!< sroot ) {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\";
    if( ! registry_key_exists( key:key ) ) {
      return FALSE;
    }
    item  = "PathName";

    sroot = registry_get_sz( item:item, key:key );
    if( "system32" >!< sroot ) {
      sroot += "\system32";
    }
  }

  if( ! isnull( sroot ) ) {
    set_kb_item( name:"SMB/SystemRoot32", value:sroot );
    return sroot;
  } else {
    return FALSE;
  }
}

# @brief Get all subkeys of HKU key, i.e. each SID listed on the host
#
# @return list All subkeys from HKU or empty list if an error occurred
#
function registry_hku_subkeys() {

  local_var list, kb_proxy_key, kb_proxy, name, port, soc, r, prot;
  local_var login, pass, domain, uid, tid, pipe, handle, _list, _item;

  # This function is mostly called in foreach loops. Make sure to always return
  # an empty list here instead of the previously behavior to return FALSE if any of
  # the calls between the last return failed. This old  behavior had caused a
  # nasl_array_iterator: # unhandled type 57 (0x39) if FALSE was returned when failed.
  list = make_list();

  # Query KB ("proxy") first.
  kb_proxy_key = "SMB//registry_hku_subkeys//Registry//";
  kb_proxy = get_kb_list( kb_proxy_key );
  if( ! isnull( kb_proxy ) && kb_proxy && typeof( kb_proxy ) == "array" )
    return kb_proxy;

  if( kb_smb_is_samba() ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#Windows SMB VT was started against a Samba Server" );
    return list;
  }

  name = kb_smb_name();
  if( ! name )
    return list;

  port = kb_smb_transport();
  if( ! port )
    return list;

  if( ! get_port_state( port ) )
    return list;

  soc = open_sock_tcp( port );
  if( ! soc )
    return list;

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();
  if( ! login ) login = "";
  if( ! pass )  pass = "";

  info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:pass, domain:domain, share:"IPC$" );

  if( isnull( info ) ) {
    close( soc );
    return list;
  }

  uid = info["uid"];
  tid = info["tid"];

  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    close( soc );
    return list;
  }

  pipe = smbntcreatex_extract_pipe( reply:r );
  if( ! pipe ) {
    close( soc );
    return list;
  }

  r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! r ) {
    close( soc );
    return list;
  }

  handle = registry_open_hku( soc:soc, uid:uid, tid:tid, pipe:pipe );
  if( ! handle ) {
    close( soc );
    return list;
  }

  _list = registry_enum_key( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:handle );
  registry_close( soc:soc, uid:uid, tid:tid, pipe:pipe, reply:handle );
  close( soc );

  if( _list ) {
    list = _list;
    foreach _item( list ) {
      set_kb_item( name:kb_proxy_key, value:_item );
    }
  }

  return list;
}
