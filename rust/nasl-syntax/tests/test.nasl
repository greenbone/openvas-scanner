# Copyright (C) 2008 E-Soft Inc.
# Copyright (C) 2008 Tim Brown
# New code since 2009 Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.50282");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:05:49 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Determine OS and list of installed packages via SSH login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH, E-Soft Inc. and Tim Brown");
  script_family("Product detection");
  script_dependencies("ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");

  script_tag(name:"summary", value:"This script will, if given a userid/password or
  key to the remote system, login to that system, determine the OS it is running, and for
  supported systems, extract the list of installed packages/rpms.");

  script_tag(name:"insight", value:"The ssh protocol is used to log in. If a specific port is
  configured for the credential, then only this port will be tried. Else any port that offers
  ssh, usually port 22.

  Upon successful login, the command 'uname -a' is issued to find out about the type and version
  of the operating system.

  The result is analysed for various patterns and in several cases additional commands are tried
  to find out more details and to confirm a detection.

  The regular Linux distributions are detected this way as well as other unixoid systems and
  also many Linux-based devices and appliances.

  If the system offers a package database, for example RPM- or DEB-based, this full list of
  installed packages is retrieved for further patch-level checks.");

  script_tag(name:"qod_type", value:"package");

  # nb: If the "Elevate Privileges" feature is enabled this routine might need a good amount of
  # additional time due to the additional SSH commands required. The higher script_timeout()
  # overwriting the default of 320 seconds (plugins_timeout = 320 of the scanner) makes sure that
  # this central VT doesn't time out too early.
  script_timeout(1800);

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");
include("version_func.inc");

SCRIPT_DESC = "Determine OS and list of installed packages via SSH login";

function register_packages( buf ) {

  local_var buf;

  if( isnull( buf ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#register_packages#-#buf" );
    return NULL;
  }

  # nb: COLUMNS=600 used below is increasing the spaces between package name and version.
  # To avoid that we're filling up too much space in the redis KB we're stripping these away.
  buf = ereg_replace( string:buf, pattern:" {3,}", replace:"  " );

  set_kb_item( name:"ssh/login/packages", value:buf );

  # nb: Generic KB key for VTs doing a detection based on the gathered RPM and DEB lists.
  set_kb_item( name:"ssh/login/rpms_or_debs/gathered", value:TRUE );

  return TRUE;
}

# @brief Saves the given RPM string into the KB.
#
# @param custom_key_name If the RPMs should be saved to a different KB-key.
# @param buf             A RPM string to save into the KB.
#
# @return TRUE if the RPM string was saved into the KB, FALSE otherwise and NULL
#         if the "buf" string was empty / wasn't passed.
#
function register_rpms( buf, custom_key_name ) {

  local_var buf, custom_key_name;
  local_var rpms_kb_key;

  if( isnull( buf ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#register_rpms#-#buf" );
    return NULL;
  }

  # nb: Have seen this only on Fusion Compute which is based on EulerOS:
  # error: cannot open Packages index using db5 - Permission denied (13)
  # error: cannot open Packages database in /var/lib/rpm
  if( "error: cannot open Packages " >< buf ) {
    set_kb_item( name:"ssh/login/failed_rpm_db_access", value:TRUE );
    set_kb_item( name:"ssh/login/failed_rpm_db_access/reason", value:chomp( buf ) );
    return FALSE;
  }

  rpms_kb_key = "ssh/login/rpms";

  if( custom_key_name )
    rpms_kb_key = custom_key_name;

  set_kb_item( name:rpms_kb_key, value:buf );

  # nb: Generic KB key for VTs doing a detection based on the gathered RPM and DEB lists.
  set_kb_item( name:"ssh/login/rpms_or_debs/gathered", value:TRUE );

  return TRUE;
}

function register_uname( uname ) {
  local_var uname;
  replace_kb_item( name:"ssh/login/uname", value:uname );
  replace_kb_item( name:"Host/uname", value:uname );
}

function create_lsc_os_detection_report( detect_text, no_lsc_support, rpm_access_error ) {

  local_var detect_text, no_lsc_support, rpm_access_error;
  local_var report;

  if( isnull( detect_text ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#create_lsc_os_detection_report#-#detect_text" );
    detect_text = "N/A (information missing from the detection)";
  }

  report = "We are able to login and detect that you are running " + detect_text;
  if( '\n' >!< detect_text )
    report += ".";

  if( rpm_access_error ) {
    report += '\n\nERROR: Access to the RPM database failed. Therefore no local security checks applied (missing list of installed packages) ';
    report += 'though SSH login provided and works.';
    report += '\n\nResponse to the "rpm" command:\n\n' + rpm_access_error;
  }

  if( no_lsc_support )
    report += '\n\nNote: Local Security Checks (LSC) are not available for this OS.';

  return report;
}

port = kb_ssh_transport();
sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

# First command: Grab uname -a of the remote system
uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, nosu:TRUE, pty:TRUE, timeout:60, retry:30 );
if( ! uname ) exit( 0 );

if( "Welcome to Viptela CLI" >< uname ) {
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  set_kb_item( name:"cisco/detected", value:TRUE );

  # Viptela (tm) vedge Operating System Software
  # Controller Compatibility:
  # Version: 20.1.1
  show_ver = ssh_cmd( socket:sock, cmd:"show system status", nosh:TRUE, nosu:TRUE, return_errors:FALSE, pty:FALSE, clear_buffer:TRUE );
  if( "vedge Operating System Software" >< show_ver ) {
    set_kb_item( name:"ssh/login/cisco/vedge/detected", value:TRUE );
    set_kb_item( name:"ssh/login/cisco/vedge/port", value:port );
    set_kb_item( name:"ssh/login/cisco/vedge/" + port + "/show_ver", value:show_ver );
  }

  exit( 0 );
}

# Kemp LoadMaster (c) 2002-2021 Kemp Technologies
# Kemp (Geo) LoadMaster Isetup -- (c) 2002-2021 Kemp Technologies
# LoadMaster configuration (KEMP)
# nb: This software has a "graphical" UI we can't use from NASL side so just doing some basic
# detection here.
if( _uname = eregmatch( string:uname, pattern:'(Kemp LoadMaster [^\r\n]+ Kemp Technologies|Kemp[^\r\n]+LoadMaster Isetup|LoadMaster configuration \\(KEMP\\))', icase:TRUE ) ) {

  set_kb_item( name:"ssh/login/kemp/loadmaster/detected", value:TRUE );
  set_kb_item( name:"ssh/login/kemp/loadmaster/port", value:port );
  set_kb_item( name:"ssh/login/kemp/loadmaster/" + port + "/concluded", value:_uname[1] );

  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

# HP iLO 100:
# Lights-Out 100 Management
# Copyright 2005-2007 ServerEngines Corporation
# Copyright 2006-2007 Hewlett-Packard Development Company, L.P.
#
# /./-> Invalid command
#
# https://blog.marquis.co/how-to-access-hps-ilo-remote-console-via-ssh/
#
# User:Administrator logged-in to ILO----n.(10.2.0.21)
# iLO 2 Standard Blade Edition 2.25 at 16:36:26 Apr 14 2014
# Server Name: vMX-Bay1
# Server Power: On
#
# hpiLO->
#
# https://community.hpe.com/t5/ProLiant-Servers-ML-DL-SL/SOLVED-Cannot-SSH-into-ILO4-v1-40-or-v1-50-after-upgrading-from/td-p/6505622
#
# User:Administrator logged-in to MYHOSTNAME(X.X.X.X / IPv6)
# iLO 4 Advanced 1.50 at  May 07 2014
# Server Name: MYHOSTNAME
# Server Power: On
#
# hpiLO->
#
# User:Administrator logged-in to MYHOSTNAME(X.X.X.X / IPv6)
# iLO 3 Advanced 1.70 at  May 07 2014
# Server Name: MYHOSTNAME
# Server Power: On
#
# hpiLO->
#
if( ( uname =~ "Lights-Out.*Management" && ( uname =~ "Copyright .+ ServerEngines Corporation" ||
                                             uname =~ "Copyright .+ Hewlett-Packard Development Company" ||
                                             "/./-> Invalid command" >< uname ) ) ||
    ( " logged-in to " >< uname && ( uname =~ "iLO [0-9]" || "hpiLO->" >< uname ) ) ) {

  # https://community.hpe.com/t5/ProLiant-Servers-ML-DL-SL/System-Firmware-Version-ssh-through-iLO/td-p/1151731
  # ftp://ftp.mrynet.com/operatingsystems/HP-MPE/docs.hp.com/en/AH232-9008A-ed3/apbs07.html
  # SYSREV should print out something like:
  # FIRMWARE INFORMATION
  #
  #    MP FW: H.03.15
  #    BMC FW: 04.05
  #    EFI FW: 05.16
  #    System FW: 62.14
  sysrev = ssh_cmd( socket:sock, cmd:"SYSREV", nosh:TRUE, nosu:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10 );
  if( sysrev )
    os_register_unknown_banner( banner:'HP iLO response to the "SYSREV" command:\n\n' + sysrev, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

# Initial setup:
# Welcome to the TippingPoint Technologies SMS Initial Setup wizard.
#
# Configured device:
# Welcome to TippingPoint Technologies SMS !
if( _uname = egrep( pattern:"Welcome to (the )?TippingPoint Technologies SMS", string:uname ) ) {

  version = ssh_cmd( socket:sock, cmd:"version", nosh:TRUE, nosu:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10, pattern:"Version:" );

  # Version:
  #     5.0.0.106258
  #
  # Patch:
  #     5.0.0.106258.1
  if( "Version:" >< version )
    set_kb_item( name:"tippingpoint/sms/ssh-login/" + port + "/version_cmd", value:version );

  set_kb_item( name:"tippingpoint/sms/ssh-login/" + port + "/uname", value:chomp( _uname ) );
  set_kb_item( name:"tippingpoint/sms/ssh-login/version_cmd_or_uname", value:TRUE );
  set_kb_item( name:"tippingpoint/sms/ssh-login/port", value:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( "HyperIP Command Line Interface" >< uname ) {

  replace_kb_item( name:"ssh/send_extra_cmd", value:'\n' );
  show_version = ssh_cmd( socket:sock, cmd:"showVersion", nosh:TRUE, nosu:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10, pattern:"Product Version" );

  # Product Version ............ HyperIP 6.1.1 11-Jan-2018 13:09 (build 2) (r9200)
  if( "Product Version" >< show_version && "HyperIP" >< show_version )
    set_kb_item( name:"hyperip/ssh-login/" + port + "/show_version", value:show_version );

  set_kb_item( name:"hyperip/ssh-login/" + port + "/uname", value:uname );
  set_kb_item( name:"hyperip/ssh-login/show_version_or_uname", value:TRUE );
  set_kb_item( name:"hyperip/ssh-login/port", value:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

# Zyxel USG and other Zyxel devices
if( "> % Command not found" >< uname ) {

  version = ssh_cmd( socket:sock, cmd:"show version", nosh:TRUE, nosu:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10 );

  # ZyXEL Communications Corp.
  # or:
  # Zyxel Communications Corp.
  if( version && version =~ "ZyXEL Communications Corp\." ) {
    set_kb_item( name:"zyxel/device/ssh-login/" + port + "/show_version_cmd", value:version );
    set_kb_item( name:"zyxel/device/ssh-login/show_version_cmd", value:TRUE );
    set_kb_item( name:"zyxel/device/ssh-login/port", value:port );

    set_kb_item( name:"ssh/restricted_shell", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

# NetApp Data ONTAP 9.x
# hostname::>
# Error: "/bin/sh" is not a recognized command
#
# or:
# hostname::*>
# Error: "/bin/sh" is not a recognized command

# NetApp Data ONTAP 7.x
# hostname>
# /bin/sh not found.  Type '?' for a list of commands

if( _uname = eregmatch( string:uname, pattern:'^.+(::\\*?> \nError: "[^"]+" is not a recognized command|>.+not found\\.  Type \'\\?\' for a list of commands)', icase:FALSE ) ) {

  version = ssh_cmd( socket:sock, cmd:"version", nosh:TRUE, nosu:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10, pattern:"NetApp Release" );

  # NetApp Release 9.0: Fri Aug 19 06:39:33 UTC 2016
  # NetApp Release 7.3: Thu Jul 24 12:55:28 PDT 2008
  if( "NetApp Release" >< version )
    set_kb_item( name:"netapp_data_ontap/ssh-login/" + port + "/version_cmd", value:version );

  set_kb_item( name:"netapp_data_ontap/ssh-login/" + port + "/uname", value:chomp( _uname[0] ) );
  set_kb_item( name:"netapp_data_ontap/ssh-login/version_cmd_or_uname", value:TRUE );
  set_kb_item( name:"netapp_data_ontap/ssh-login/port", value:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

# e.g. Cisco Prime Infrastructure if another admin is logged in
if( "Another user is logged into the system at this time" >< uname && "Are you sure you want to continue" >< uname ) {
  replace_kb_item( name:"ssh/send_extra_cmd", value:'Yes\n' );
  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, pty:TRUE, timeout:20, retry:10 );
}

if( "Following disconnected ssh sessions are available to resume" >< uname ) {
  replace_kb_item( name:"ssh/send_extra_cmd", value:'\n' );
  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, pty:TRUE, timeout:20, retry:10 );
}

if( "Welcome to Data Domain OS" >< uname ) {
  set_kb_item( name:"emc/data_domain_os/uname", value:uname );
  log_message( port:port, data:create_lsc_os_detection_report( detect_text:"EMC Data Domain OS" ) );
  exit( 0 );
}

# *** Welcome to pfSense 2.4.4-RELEASE-p3 (amd64) on pfSense ***
# *** Welcome to pfSense 2.4.2-RELEASE (amd64) on pfSense ***
if( un = egrep( string:uname, pattern:"Welcome to pfSense", icase:TRUE ) ) {

  # nb: For some reason we're getting the output twice (probably because of the missing "clear_buffer" below
  # so split and use only the first hit.
  _un = split( un, keep:FALSE );
  if( _un[0] =~ "pfsense" )
    set_kb_item( name:"pfsense/uname", value:_un[0] );
  else
    set_kb_item( name:"pfsense/uname", value:un );

  set_kb_item( name:"pfsense/ssh/port", value:port);
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"ssh/force/nolang_sh", value:TRUE );

  # clear the buffer to avoid that we're saving the whole pfSense menu in the uname
  set_kb_item( name:"ssh/force/clear_buffer", value:TRUE );

  # 8) Shell
  # nb: We're using a regex here to make sure that we're catching the correct number
  # if they decide to change or make it dynamic in a later release.
  shell = eregmatch( string:uname, pattern:"([0-9])+\) Shell", icase:TRUE );
  if( ! isnull( shell[1] ) )
    replace_kb_item( name:"ssh/send_extra_cmd", value:shell[1] + '\n' );

  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, pty:TRUE, timeout:20, retry:10 );
  # nb: FreeBSD will be caught later below
  is_pfsense = TRUE;
}

if( "Welcome to the Greenbone OS" >< uname ) {
  set_kb_item( name:"greenbone/gos/uname", value:uname );
  set_kb_item( name:"greenbone/gos", value:TRUE );

  # Don't use a pty which avoids that we're getting the GOS admin menu back in our uname command
  # and to save the "real" uname later
  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:FALSE, pty:FALSE, timeout:20, retry:10 );

  # This is from GOS 3.1.x where we need to use a pty and pass an extra command for each ssh_cmd call
  if( "Type 'gos-admin-menu' to start the Greenbone OS Administration tool" >< uname ) {
    replace_kb_item( name:"ssh/send_extra_cmd", value:'shell\n' );
    uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:FALSE, pty:TRUE, timeout:20, retry:10 );
  }
}

if( "HyperFlex-Installer" >< uname ) {
  set_kb_item( name:"ssh/login/cisco/hyperflex_installer/detected", value:TRUE );
  set_kb_item( name:"ssh/login/cisco/hyperflex_installer/port", value:port );
  # nb: Don't use exit(0); here as the software is running on Ubuntu which is checked later
}

# FreeBSD CitrixADM 11.4-NETSCALER-13.1 FreeBSD 11.4-NETSCALER-13.1 #0 2f47ac573953(heads/artesa_4_43)-dirty: Fri Sep 10 06:18:49 PDT 2021     root@sjc-bld-bsd114-207:/usr/obj/usr/home/build/adc/usr.src/sys/NSSVM  amd64
if( " CitrixADM " >< uname ) {
  set_kb_item( name:"ssh/login/citrix/adm/detected", value:TRUE );
  set_kb_item( name:"ssh/login/citrix/adm/port", value:port );
  exit( 0 ); # nb: This is seems to be a customized image so we don't want to do further FreeBSD checks
}

if( "linux" >< tolower( uname ) ) {
  un = egrep( pattern:'(Linux[^\r\n]+)', string:uname );
  if( un ) {

    # Linux hostname 4.19.46 #1-NixOS SMP Sat May 25 16:23:48 UTC 2019 x86_64 GNU/Linux
    # Linux hostname 4.19.0-5-amd64 #1 SMP Debian 4.19.37-3 (2019-05-15) x86_64 GNU/Linux
    u = eregmatch( pattern:'(Linux [^ ]+ [^ ]+ #[0-9]+[^ ]* [^\n]+)', string:un );

    if( ! isnull( u[1] ) ) {
      register_uname( uname:u[1] );
    }
  }
}

if( "(Cisco Controller)" >< uname )
  exit( 0 );

# To catch the uname above before doing an exit
if( get_kb_item( "greenbone/gos" ) )
  exit( 0 );

# nb: It wasn't clear if this was only seen on GOS so keep this for now.
# nb2: This exists at least on TippingPoint Security Management System (SMS) as well.
if( "restricted: cannot specify" >< uname ) {
  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  exit( 0 );
}

if( "TANDBERG Video Communication Server" >< uname ) {
  set_kb_item( name:"cisco/ssh/vcs", value:TRUE );
  set_kb_item( name:"ssh/send_extra_cmd", value:'\n' );
  exit( 0 );
}

if( "Cyberoam Central Console" >< uname )
{
  set_kb_item( name:"cyberoam_cc/detected", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

  ccc = eregmatch( pattern:'([0-9]+)\\.\\s*CCC Console', string:uname );
  if( ! isnull( ccc[1] ) )
  {
    version_info = ssh_cmd( socket:sock, cmd:ccc[1] + '\nccc diagnostics show version-info', nosh:TRUE, nosu:TRUE, pty:TRUE, timeout:60, retry:20, pattern:"Hot Fix version" );
    if( "CCC version:" >< version_info )
      set_kb_item( name:"cyberoam_cc/version_info", value:version_info );
  }
  exit( 0 );
}

if( "Welcome to the Immediate Insight Management Console" >< uname || ( "type 'start' to start the server" >< uname && "'status' checks the current setup" >< uname ) )
{
  set_kb_item( name:"firemon/immediate_insight/detected", value:TRUE );
  exit( 0 );
}

if( 'Error: Unknown: "/bin/sh"' >< uname )
{
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"enterasys/detected", value:TRUE );
  exit( 0 );
}

if( "Cisco UCS Director Shell Menu" >< uname )
{
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

  v = eregmatch( pattern:'([0-9]+)\\) Show Version', string:uname );
  if( ! isnull( v[1] ) )
  {
    show_version = ssh_cmd( socket:sock, cmd:v[1], nosh:TRUE, nosu:TRUE, pty:TRUE, timeout:60, retry:20, pattern:"Press return to continue", clear_buffer:TRUE );
    if( show_version && "Version" >< show_version && "Build" >< show_version )
    {
      set_kb_item( name:"cisco_ucs_director/ssh_login/port", value:port );
      set_kb_item( name:"cisco_ucs_director/show_version", value:show_version );
      exit( 0 );
    }
  }
}

if( "WatchGuard Fireware OS" >< uname ) {
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  set_kb_item( name:"ssh/force/pty", value:TRUE );

  set_kb_item( name:"watchguard/fireware/detected", value:TRUE );
  set_kb_item( name:"watchguard/fireware/ssh-login/port", value:port );

  res = ssh_cmd( socket:sock, cmd:"exit", return_errors:TRUE, pty:TRUE, nosh:TRUE, nosu:TRUE,
                 timeout:20 );
  cmd = "show sysinfo";
  show_sysinfo = ssh_cmd( socket:sock, cmd:cmd, return_errors:TRUE, pty:TRUE, nosh:TRUE, nosu:TRUE,
                          timeout:20, retry:20, clear_buffer:TRUE );
  set_kb_item( name:"watchguard/fireware/ssh-login/" + port + "/show_sysinfo", value:show_sysinfo );

  exit( 0 );
}

if( "% invalid command at '^' marker" >< tolower( uname ) || "No token match at '^' marker" >< uname ||
    "NX-OS" >< uname || "Cisco Nexus Operating System" >< uname || "Line has invalid autocommand" >< uname ||
    "The command you have entered is available in the IOS.sh" >< uname ||
    ( "For more information, enable shell, and then enter:" >< uname && "'man IOS.sh'" >< uname ) ) {

  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"cisco/detected", value:TRUE );
  set_kb_item( name:"cisco/ssh-login/port", value:port );

  # The CISCO device is closing the connection after this message.
  # Unfortunately we can't detect if the device has configured a working autocommand but we still
  # want to report a broken one to the user (in gb_authenticated_scan_lsc_ssh_login_consolidation.nasl).
  if( "Line has invalid autocommand" >< uname )
    set_kb_item( name:"ssh/cisco/broken_autocommand", value:TRUE );

  exit( 0 );
}

# Some(?) Cisco IOS XR devices seem to not handle PTY commands well (returning only the prompt and not any errors)
# So we use the usual prompt (e.g. RP/0/RP0/CPU0:ios#) as a marker
if( egrep( pattern:"^RP/0/[A-Z0-9]+/CPU[0-9]", string:uname ) ) {
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  set_kb_item( name:"ssh/force/pty", value:FALSE );
  set_kb_item( name:"cisco/detected", value:TRUE );
  set_kb_item( name:"cisco/ssh-login/port", value:port );

  exit( 0 );
}

if( "Command Line Interface is starting up" >< uname || "Invalid command, a dash character must be preceded" >< uname )
{
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

  system = ssh_cmd( socket:sock, cmd:'show tech ccm_service', nosh:TRUE, nosu:TRUE, pty:TRUE, timeout:60, retry:50 );

  if( "GroupName: CM Services" >< system )
  {
    set_kb_item( name:"ssh/login/cisco/cucm/detected", value:TRUE );
    set_kb_item( name:"ssh/login/cisco/cucm/port", value:port );
    set_kb_item( name:"ssh/login/cisco/cucm/" + port + "/show_tech_ccm_service", value:system );
    exit( 0 );
  }

  if( "GroupName: IM and Presence Services" >< system )
  {
    set_kb_item( name:"cisco/cucmim/show_tech_ccm_service", value:system );
    set_kb_item( name:"cisco/cucmim/detected", value:TRUE );
    exit( 0 );
  }

  if( "GroupName: Cisco Finesse Services" >< system )
  {
    set_kb_item( name:"cisco/finesse/show_tech_ccm_service", value:system );
    set_kb_item( name:"cisco/finesse/detected", value:TRUE );
    exit( 0 );
  }
  exit( 0 );
}

if( uname =~ "Cisco Prime( Virtual)? Network Analysis Module" )
{
  show_ver = ssh_cmd( socket:sock, cmd:'show version', nosh:TRUE, nosu:TRUE, pty:TRUE, timeout:30, retry:10, pattern:'Installed patches:' );
  if( "NAM application image" >< show_ver )
  {
    set_kb_item( name:"cisco_nam/show_ver", value:show_ver );
    set_kb_item( name:"cisco_nam/ssh-login/port", value:port );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

if( "CMC Build" >< uname && "LEM" >< uname && "Exit CMC" >< uname )
{
  set_kb_item( name:"solarwinds_lem/installed", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

  sysinfo = ssh_cmd( socket:sock, cmd:'manager\nviewsysinfo', nosh:TRUE, nosu:TRUE, pty:TRUE, timeout:90, retry:10, pattern:'/tmp/swi-lem-sysinfo.txt' );
  vers = eregmatch( pattern:'TriGeo manager version is: ([^\r\n]+)', string:sysinfo );
  if( ! isnull( vers[1] ) ) set_kb_item( name:"solarwinds_lem/version/ssh", value:vers[1] );

  build = eregmatch( pattern:'TriGeo manager build is: ([^\r\n]+)', string: sysinfo );
  if( ! isnull( build[1] ) )
  {
    set_kb_item( name:"solarwinds_lem/build/ssh", value:build[1] );
    hotfix = eregmatch( pattern:'hotfix([0-9]+)', string:build[1] );
    if( ! isnull( hotfix[1] ) ) set_kb_item( name:"solarwinds_lem/hotfix/ssh", value:hotfix[1] );
  }

  ubuild =  eregmatch( pattern:'TriGeo upgrade build is: ([^\r\n]+)', string: sysinfo );
  if( ! isnull( ubuild[1] ) ) set_kb_item( name:"solarwinds_lem/ubuild/ssh", value:ubuild[1] );

  cmc = eregmatch( pattern:'CMC version: ([^\r\n]+)', string:sysinfo );
  if( ! isnull( cmc[1] ) ) set_kb_item( name:"solarwinds_lem/cmc_version/ssh", value:cmc[1] );

  exit( 0 );
}

if( "Sourcefire Linux OS" >< uname )
{
  set_kb_item( name:"sourcefire_linux_os/installed", value:TRUE );

  cpe = 'cpe:/o:sourcefire:linux_os';
  version = eregmatch( pattern:'Sourcefire Linux OS v([^ ]+)', string:uname );

  if( ! isnull( version[1] ) )
  {
    cpe += ':' + version[1];
    set_kb_item( name:"sourcefire_linux_os/version", value:version[1] );
  }

  build = eregmatch( pattern:'\\(build ([^)]+)\\)', string:uname );

  if( ! isnull( build[1] ) ) set_kb_item( name:"sourcefire_linux_os/build", value:build[1] );

  os_register_and_report( os:"Sourcefire Linux OS", cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

  report = "Sourcefire Linux OS";
  if( version[1] ) report += '\nVersion: ' + version[1];
  if( build[1] ) report += '\nBuild: ' + build[1];

  log_message( port:port, data:create_lsc_os_detection_report( detect_text:report ) );
  exit( 0 );
}

if( "Cisco Firepower Management Center" >< uname )
{
  set_kb_item( name:'cisco_fire_linux_os/detected', value:TRUE );
  set_kb_item( name:"cisco/detected", value:TRUE );
  if( "Cisco Fire Linux OS" >< uname )
  {
    cpe = 'cpe:/o:cisco:fire_linux_os';
    version = eregmatch( pattern:'Cisco Fire Linux OS v([^ ]+)', string:uname );
    if( ! isnull( version[1] ) )
    {
      cpe += ':' + version[1];
      set_kb_item( name:"cisco/fire_linux_os/version", value:version[1] );
    }

    build = eregmatch( pattern:'\\(build ([^)]+)\\)', string: uname);
    if( ! isnull( build[1] ) ) set_kb_item( name:"cisco/fire_linux_os/build", value:build[1] );

    os_register_and_report( os:"Cisco Fire Linux OS", cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

    report = "Cisco Fire Linux OS";
    if( version[1] ) report += '\nVersion: ' + version[1];
    if( build[1] ) report += '\nBuild: ' + build[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:report ) );
    exit( 0 );
  }
}

if( uname =~ "Cisco NGIPS(v)?" && "Cisco Fire Linux OS" >< uname )
{
  if( "Cisco Fire Linux OS" >< uname )
  {
    cpe = 'cpe:/o:cisco:fire_linux_os';
    version = eregmatch(pattern: 'Cisco Fire Linux OS v([^ ]+)', string: uname );
    if( ! isnull( version[1] ) )
    {
      cpe += ':' + version[1];
      set_kb_item(name: "cisco/fire_linux_os/version", value: version[1]);
    }

    build = eregmatch(pattern: '\\(build ([^)]+)\\)', string: uname);
    if( ! isnull( build[1] ) ) set_kb_item(name: "cisco/fire_linux_os/build", value: build[1] );

    os_register_and_report(os: "Cisco Fire Linux OS", cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );

    report = "Cisco Fire Linux OS";
    if( version[1] ) report += '\nVersion: ' + version[1];
    if( build[1] ) report += '\nBuild: ' + build[1];

    log_message(port: port, data: create_lsc_os_detection_report(detect_text: report));
  }

  set_kb_item(name: "cisco/ngips/uname", value: uname);
  exit( 0 );
}

if( "CLINFR0329  Invalid command" >< uname )
{
  show_ver = ssh_cmd(socket: sock, cmd: "show version all", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: FALSE);
  if( show_ver && "Check Point Gaia" >< show_ver )
  {
    gaia_cpe = "cpe:/o:checkpoint:gaia_os";
    set_kb_item(name: "checkpoint_fw/detected", value: TRUE);
    replace_kb_item(name: "ssh/lsc/use_su", value: "no");

    version = eregmatch(pattern: 'Product version Check Point Gaia (R[^\r\n]+)', string: show_ver);
    if( ! isnull( version[1] ) )
    {
      gaia_cpe += ':' + tolower(version[1]);
      set_kb_item(name: "checkpoint_fw/ssh/version", value: version[1]);
    }

    os_register_and_report(os: "Check Point Gaia", cpe: gaia_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );

    build = eregmatch(pattern: 'OS build ([^\r\n]+)', string: show_ver);
    if( ! isnull( build[1] ) ) set_kb_item( name:"checkpoint_fw/ssh/build", value:build[1] );

    report = "Check Point Gaia";
    if( version[1] ) report += '\nVersion: ' + version[1];
    if( build[1] ) report += '\nBuild: ' + build[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:report ) );
    exit( 0 );
  }
}

if( "% Unknown command" >< uname )
{
  show_ver = ssh_cmd( socket:sock, cmd:"show version", return_errors:FALSE, pty:TRUE, nosh:TRUE, nosu:TRUE, timeout:20, retry:10, pattern:"NSX Manager" );
  if( show_ver && "NSX Manager" >< show_ver ) {
    set_kb_item( name:"vmware/nsx/ssh/port", value:port );
    set_kb_item( name:"vmware/nsx/show_ver", value:show_ver );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

# nb: Normally we should only get the first pattern back as a response to the initial
# uname -a probe. But if something like e.g. the following is used:
#
# su - foo -s /bin/bash -c 'uname -a'
#
# the response changes to the second pattern. To make this future proof we're checking both.
if( "Error: Unrecognized command found at '^' position." >< uname ||
    "Error: Wrong parameter found at '^' position." >< uname ) {

  cmd = "display version";
  display_vers = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, nosu:TRUE,
                          timeout:20, retry:10, force_reconnect:TRUE, clear_buffer:TRUE );
  if( "Huawei Versatile Routing Platform" >< display_vers ) {

    # nb:
    # <HUAWEI>
    # <Huawei>
    # <SOME-TEXT>
    display_vers = ereg_replace( string:display_vers, pattern:'\n[^\r\n]+$', replace:"" );
    set_kb_item( name:"huawei/vrp/display_version", value:display_vers );

    set_kb_item( name:"huawei/vrp/ssh/port", value:port );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    set_kb_item( name:"ssh/force/reconnect", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    concluded_command = "'" + cmd + "'";

    cmd = "display patch-information";
    patch_info = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, nosu:TRUE,
                          timeout:20, retry:10, force_reconnect:TRUE, clear_buffer:TRUE );
    if (patch_info) {
      if (concluded_command)
        concluded_command += ", ";
      concluded_command += "'" + cmd + "'";

      patch_info = ereg_replace( string:patch_info, pattern:'\n[^\r\n]+$', replace:"" );
      set_kb_item( name:"huawei/vrp/patch-information", value:patch_info );
    }

    cmd = "display device";
    display_dev = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, nosu:TRUE,
                           timeout:20, retry:10, force_reconnect:TRUE, clear_buffer:TRUE );
    if (display_dev) {
      if (concluded_command)
        concluded_command += ", ";
      concluded_command += "'" + cmd + "'";

      display_dev = ereg_replace( string:display_dev, pattern:'\n<[^\r\n]+>$', replace:"" );
      set_kb_item( name:"huawei/vrp/display_device", value:display_dev );
    }

    set_kb_item( name:"huawei/vrp/ssh-login/" + port + "/concluded_command", value:concluded_command );

    exit( 0 );
  }
}

if( "JUNOS" >< uname && "Junos Space" >!< uname )
{
  if( "unknown command" >< uname )
  {
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    set_kb_item( name:"junos/cli", value:TRUE );
  }
  set_kb_item( name:"junos/detected", value:TRUE );
  exit( 0 );
}

if( "Wedge Networks" >< uname && "BeSecure" >< uname && "To access the management console" >< uname )
{
  status = ssh_cmd( socket:sock, cmd:"status show", nosh:TRUE, nosu:TRUE );
  if( "Scanner" >< status && "BeSecure" >< status )
  {
    set_kb_item( name:"wedgeOS/status", value:status );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

if( 'ERROR: "/" not recognized' >< uname )
{
  sv = ssh_cmd( socket:sock, cmd:"show version", nosh:TRUE, nosu:TRUE, pty:TRUE, pattern:"F5 Networks LROS Version" );
  if( "F5 Networks LROS Version" >< sv )
  {
    set_kb_item( name:"f5/LROS/show_version", value:sv );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

if( "ERROR: No such command" >< uname )
{
  system = ssh_cmd( socket:sock, cmd:"show ns version", nosh:TRUE, nosu:TRUE );
  if( "NetScaler" >< system )
  {
    set_kb_item( name:"citrix_netscaler/system", value: system );
    set_kb_item( name:"citrix_netscaler/found", value:TRUE );
    set_kb_item( name:"citrix_netscaler/ssh/port", value: port );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    hw = ssh_cmd( socket:sock, cmd:"show ns hardware", nosh:TRUE, nosu:TRUE );
    if( hw )
      set_kb_item( name:"citrix_netscaler/hardware", value: hw );

    features = ssh_cmd( socket:sock, cmd:"show ns feature", nosh:TRUE, nosu:TRUE );
    if( features )
      set_kb_item( name:"citrix_netscaler/features", value: features );

   exit( 0 );
  }
}

if( "-----unknown keyword " >< uname )
{
  set_kb_item( name:"ScreenOS/detected", value:TRUE );
  exit( 0 );
}

if( "Unknown command:" >< uname && "IBM Security Network Protection" >< uname )
{
  set_kb_item( name:"isnp/detected", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( "Unknown command: " >< uname || "Unknown command or missing feature key" >< uname )
{
  system = ssh_cmd( socket:sock, cmd:"show system info", nosh:TRUE, nosu:TRUE, pty:TRUE, pattern:"model: PA", retry:8 );
  if( eregmatch( pattern:'model: PA-', string:system ) && "family:" >< system )
  {
    set_kb_item( name:"palo_alto/detected", value:TRUE );
    set_kb_item( name:"palo_alto/ssh/detected", value:TRUE );
    set_kb_item( name:"palo_alto/ssh/port", value:port );
    set_kb_item( name:"palo_alto/ssh/system", value:system );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }

  system = ssh_cmd( socket:sock, cmd:"version", nosh:TRUE, nosu:TRUE );
  if( ( "Cisco" >< system || "IronPort" >< system ) && system =~ 'Security( Virtual)? Management' )
  {
    set_kb_item( name:"cisco_csm/detected", value:TRUE );
    set_kb_item( name:"cisco_csm/ssh-login/detected", value:TRUE );
    set_kb_item( name:"cisco_csm/ssh-login/port", value:port );
    set_kb_item( name:"cisco_csm/ssh-login/" + port + "/concluded", value:system );

    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    version = "unknown";
    model   = "unknown";
    vers = eregmatch( pattern:'Version: ([^\r\n]+)', string:system );
    if( ! isnull( vers[1] ) )
      version = vers[1];

    mod = eregmatch( pattern:'Model: ([^\r\n]+)', string:system );
    if( ! isnull( mod[1] ) )
      model = mod[1];

    set_kb_item( name:"cisco_csm/ssh-login/" + port + "/version", value:version );
    set_kb_item( name:"cisco_csm/ssh-login/" + port + "/model", value:model );

    exit( 0 );
  }

  if( ( "Cisco" >< system || "IronPort" >< system ) && system =~ 'Email Security( Virtual)? Appliance' )
  {
    set_kb_item( name:"cisco_esa/system", value:system );
    set_kb_item( name:"cisco_esa/installed", value:TRUE );

    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    version = eregmatch( pattern:'Version: ([^\r\n]+)', string:system );
    if( ! isnull( version[1] ) ) set_kb_item( name:"cisco_esa/version/ssh", value:version[1] );

    model = eregmatch( pattern:'Model: ([^\r\n]+)', string:system );
    if( ! isnull( model[1] ) ) set_kb_item( name:"cisco_esa/model/ssh", value:model[1] );

    exit( 0 );
  }

  if( ( "Cisco" >< system || "IronPort" >< system ) && system =~ 'Web Security( Virtual)? Appliance' )
  {
    set_kb_item( name:"cisco_wsa/system", value:system );
    set_kb_item( name:"cisco_wsa/installed", value:TRUE );

    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    version = eregmatch( pattern:'Version: ([^\r\n]+)', string:system );
    if( ! isnull( version[1] ) ) set_kb_item( name:"cisco_wsa/version/ssh", value:version[1] );

    model = eregmatch( pattern:'Model: ([^\r\n]+)', string:system );
    if( ! isnull( model[1] ) ) set_kb_item( name:"cisco_wsa/model/ssh", value:model[1] );

    exit( 0 );
  }
}

if( ( "diagnose" >< uname || "traceroute6" >< uname ) && "enable" >< uname && "exit" >< uname && "^" >< uname)
{
  system = ssh_cmd( socket:sock, cmd:"show system version", nosh:TRUE, nosu:TRUE, pty:FALSE );
  if( "Operating System" >< system && "IWSVA" >< system )
  {
    set_kb_item( name:"IWSVA/system", value:system );
    set_kb_item( name:"IWSVA/ssh-login/port", value:port );
    set_kb_item( name:"IWSVA/cli_is_clish", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }

  system = ssh_cmd( socket:sock, cmd:"show module IMSVA version", nosh:TRUE, nosu:TRUE, pty:FALSE );

  if( system =~ "IMSVA [0-9.]+-Build_Linux_[0-9]+" )
  {
    set_kb_item( name:"IMSVA/system", value:system );
    set_kb_item( name:"IMSVA/ssh-login/port", value:port );
    set_kb_item( name:"IMSVA/cli_is_clish", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }

}

if( "Invalid input detected at" >< uname )
{
  set_kb_item( name:"cisco/detected", value:TRUE );
  set_kb_item( name:"cisco/ssh-login/port", value:port );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( "% invalid command detected" >< uname )
{
  show_ver = ssh_cmd( socket:sock, cmd:"show version", nosh:TRUE, nosu:TRUE, pty:TRUE, pattern:"Internal Build", timeout:60, retry:20 );
  if( "ERROR : Please enter Yes or No" >< show_ver )
    show_ver = ssh_cmd( socket:sock, cmd:'Yes\nshow version', nosh:TRUE, nosu:TRUE, pty:TRUE, pattern:"build", timeout:60, retry:20 );

  if( "Cisco ACS VERSION INFORMATION" >< show_ver )
  {
    set_kb_item( name:"cisco_acs/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    os_register_and_report( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Identity Services Engine" >< show_ver )
  {
    set_kb_item( name:"cisco_ise/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    os_register_and_report( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Prime Collaboration Provisioning" >< show_ver )
  {
    set_kb_item( name:"cisco_pcp/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    os_register_and_report( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Prime Collaboration Assurance" >< show_ver )
  {
    set_kb_item( name:"cisco_pca/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    os_register_and_report( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Prime Infrastructure" >< show_ver )
  {
    set_kb_item( name:"cisco_pis/show_ver", value:show_ver );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    os_register_and_report( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if ("Cisco Prime Network Control System" >< show_ver )
  {
    set_kb_item( name:"cisco_ncs/show_ver", value:show_ver );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    os_register_and_report( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  exit( 0 );
}

# Some Cisco devices (e.g. Cisco FTD) don't respond correctly if an unknown command is executed
if( "uname-a" >< uname ) {
  # We need a clean new connection otherwise the cli stucks
  ssh_reconnect( sock:sock);
  show_ver = ssh_cmd( socket:sock, cmd:"show version", nosh:TRUE, nosu:TRUE, pty:TRUE, pattern:"Cisco", clear_buffer:TRUE );
  if( show_ver ) {
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    set_kb_item( name:"cisco/detected", value:TRUE );
  }

  exit( 0 );
}

if( ": No such command" >< uname ) {
  system = ssh_cmd( socket:sock, cmd:"status", nosh:TRUE, nosu:TRUE, pty:TRUE, pattern:"Version:\s*FAC" );
  if( system =~ "Version:\s*FAC" && "Architecture" >< system && "Branch point" >< system ) {
    set_kb_item(name:"FortiOS/Authenticator/system", value:system );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/login/release", value:"FortiOS" );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    os_register_and_report( os:"Fortinet FortiOS", cpe:"cpe:/o:fortinet:fortios", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

    exit( 0 );
  }
}

if( "Unknown action 0" >< uname ) {
  system = ssh_cmd( socket:sock, cmd:"get system status", nosh:TRUE, nosu:TRUE );
  if( "Forti" >< system ) {
    set_kb_item( name:"fortinet/fortios/system_status", value:system );
    set_kb_item( name:"fortinet/fortios/ssh-login/port", value:port );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/login/release", value:"FortiOS" );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    os_register_and_report( os:"Fortinet FortiOS", cpe:"cpe:/o:fortinet:fortios", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

    f_version = eregmatch( pattern:"Version\s*:\s*(Forti[^ ]* )?v([0-9.]+)", string:system );
    if( ! isnull( f_version[2] ) )
      set_kb_item( name:"forti/FortiOS/version", value:f_version[2] );

    f_build = eregmatch( string:system, pattern:"[-,]+build([^-, ]+)" );
    if( ! isnull( f_build[1] ) )
      set_kb_item( name:"forti/FortiOS/build", value:f_build[1] );

    f_typ = eregmatch( string:system, pattern:"Platform Full Name\s*:\s*(Forti[^- ]+)" );
    if( ! isnull( f_typ[1] ) )
      set_kb_item( name:"forti/FortiOS/typ", value:f_typ[1] );

    exit( 0 );
  }
}

if( "Invalid input:" >< uname ) {
  system = ssh_cmd( socket:sock, cmd:"show system", nosh:TRUE, nosu:TRUE );
  if( system =~ "Vendor\s*:\s*Aruba" ) {
    set_kb_item( name:"arubaos/system", value:system );
    set_kb_item( name:"arubaos/ssh-login/port", value:port );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/login/release", value:"ArubaOS" );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );

    os_register_and_report( os:"Aruba/HP/HPE ArubaOS Firmware", cpe:"cpe:/o:arubanetworks:arubaos_firmware",
                            banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide");

    exit( 0 );
  }
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /opt/vmware/etc/appliance-manifest.xml", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/opt/vmware/etc/appliance-manifest.xml: ' + rls + '\n\n';
}

if( rls =~ "<product>vSphere Data Protection [^<]+</product>" ) {
  set_kb_item( name:"vmware/vSphere_Data_Protection/rls", value:rls );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/Novell-VA-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/Novell-VA-release: ' + rls + '\n\n';
}

if( "singleWordProductName=Filr" >< rls ) {
  set_kb_item( name:"filr/ssh/rls", value:rls );
  set_kb_item( name:"filr/ssh/port", value:port );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/vmware/text_top", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/vmware/text_top: ' + rls + '\n\n';
}

if( "VMware vRealize Log Insight" >< rls ) {
  set_kb_item( name:"vmware/vrealize_log_insight/rls", value:rls );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"vmware -v", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += 'vmware -v: ' + rls + '\n\n';
}

# VMware ESXi 6.7.0 build-10302608
if( _rls = egrep( string:rls, pattern:"^VMware ESX", icase:FALSE ) ) {
  set_kb_item( name:"vmware/esxi/ssh-login/" + port + "/version_banner", value:chomp( _rls ) );
  set_kb_item( name:"vmware/esxi/ssh-login/version_banner", value:TRUE );
  set_kb_item( name:"vmware/esxi/ssh-login/port", value:port );
  exit( 0 );
}

if( "linux" >< tolower( uname ) ) {
  # Cisco MSE 10.x
  mse_status = ssh_cmd( socket:sock, cmd:"cmxctl version", return_errors:FALSE, nosh:TRUE, nosu:TRUE, pty:TRUE );
  if( "Build Version" >< mse_status && "cmx-" >< mse_status && "Build Time" >< mse_status ) {
    set_kb_item( name:"cisco_mse/status", value:mse_status );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }

  # Cisco MSE <= 8.x
  mse_status = ssh_cmd( socket:sock, cmd:"getserverinfo", return_errors:FALSE, pty:TRUE, timeout:30, retry:10, pattern:"Total Elements" );
  if( "Product name: Cisco Mobility Service Engine" >< mse_status ) {
    set_kb_item( name:"cisco_mse/status", value:mse_status );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/github/enterprise-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/github/enterprise-release: ' + rls + '\n\n';
}

if( "RELEASE_VERSION" >< rls && "RELEASE_BUILD_ID" >< rls ) {
  set_kb_item( name:"github/enterprise/rls", value:rls );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/cisco-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/cisco-release: ' + rls + '\n\n';
}

if( "Cisco IPICS Enterprise Linux Server" >< rls ) { # Cisco IPICS Enterprise Linux Server release 4.5(1) Build 10p12
  set_kb_item( name:"cisco/ipics/detected", value:TRUE );
  os_register_and_report( os:rls, cpe:"cpe:/o:cisco:linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  log_message( port:port, data:create_lsc_os_detection_report( detect_text:rls ) );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/.qradar_install_version", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/.qradar_install_version: ' + rls + '\n\n';
}

if( rls =~ '^[0-9]\\.[0-9]\\.[0-9]\\.20(1|2)[0-9]+' ) {
  rls = chomp( rls );
  set_kb_item( name:"qradar/version", value:rls );
  typ = ssh_cmd( socket:sock, cmd:"cat /etc/.product_name", return_errors:FALSE );
  if( ! isnull( typ ) ) set_kb_item( name:'qradar/product_name', value:typ );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/nitrosecurity-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/nitrosecurity-release: ' + rls + '\n\n';
}

if( "McAfee ETM " >< rls ) {
  buildinfo = ssh_cmd( socket:sock, cmd:"cat /etc/NitroGuard/.buildinfo", return_errors:FALSE );
  if( "VERSION" >< buildinfo && "MAINTVER" >< buildinfo ) {
    set_kb_item( name:"mcafee/etm/buildinfo", value:buildinfo );
    exit( 0 );
  }
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/system-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/system-release: ' + rls + '\n\n';
}

if( "IPFire" >< rls ) { # IPFire 2.17 (i586) - core91
  set_kb_item( name:"ipfire/system-release", value:rls );
  log_message( port:port, data:create_lsc_os_detection_report( detect_text:rls ) );
  os_register_and_report( os:rls, cpe:"cpe:/o:ipfire:linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g. "Amazon Linux AMI release" or "Amazon Linux release 2 (Karoo)" among possible later releases
# This only covers Amazon Linux AMI for now. Not the later releases.
#
# NOTE: Amazon Linux also perfectly supports /etc/os-release, so that could also be used.
if( "Amazon Linux AMI release" >< rls ) {

  set_kb_item( name:"ssh/login/amazon_linux", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;

    # Package gathering for Notus
    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_rpms( buf:buf, custom_key_name:"ssh/login/package_list_notus" ) )
        error = buf;
    }
  }

  set_kb_item( name:"ssh/login/release", value:"AMAZON" );

  # Release string for Notus
  set_kb_item( name:"ssh/login/release_notus", value:"Amazon Linux" );

  log_message( port:port, data:create_lsc_os_detection_report( rpm_access_error:error, detect_text:"Amazon Linux" ) );

  os_register_and_report( os:"Amazon Linux", cpe:"cpe:/o:amazon:linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# EON runs on CentOS
if( "EyesOfNetwork release" >< rls ) {

  set_kb_item( name:"eyesofnetwork/ssh/port", value:port );
  set_kb_item( name:"eyesofnetwork/ssh/" + port + "/concludedFile", value:"/etc/system-release" );
  set_kb_item( name:"eyesofnetwork/rls", value:rls );

  set_kb_item( name:"ssh/login/centos", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  buf = ssh_cmd( socket:sock, cmd:"cat /etc/system-release-cpe", return_errors:FALSE );

  # EON 4.0 has a wrong cpe:/o:centos:linux in the system-release-cpe
  buf = str_replace( string:buf, find:"centos:linux", replace:"centos:centos" );

  os_ver = eregmatch( pattern:"cpe:/o:centos:centos:([0-9])", string:buf );
  if( ! isnull( os_ver[1] ) ) {
    oskey = "CentOS" + os_ver[1];
    log_message( port:port, data:create_lsc_os_detection_report( rpm_access_error:error, detect_text:"CentOS release " + os_ver[1] ) );
    set_kb_item( name:"ssh/login/release", value:oskey );
    os_register_and_report( os:"CentOS release " + os_ver[1], cpe:buf, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    log_message( port:port, data:create_lsc_os_detection_report( rpm_access_error:error, detect_text:"CentOS" ) );
  }
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/pgp-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/pgp-release: ' + rls + '\n\n';
}

if( "Symantec Encryption Server" >< rls ) {
  set_kb_item( name:"symantec_encryption_server/installed", value:TRUE );
  set_kb_item( name:"symantec_encryption_server/rls", value:rls );

  mp = ssh_cmd( socket:sock, cmd:"cat /etc/oem-suffix", return_errors:FALSE );
  if( ! isnull( mp ) )
    set_kb_item( name:"symantec_encryption_server/MP", value:chomp( mp ) );

  oem_release = ssh_cmd( socket:sock, cmd:"cat /etc/oem-release", return_errors:FALSE );
  if( ! isnull( oem_release ) )
    set_kb_item( name:"symantec_encryption_server/oem-release", value:chomp( oem_release ) );

  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /VERSION", return_errors:TRUE );

  # nb: This is a special case, normally ssh_cmd() would catch all of these but the code below requires
  # the errors to be returned (thus return_errors:TRUE).
  if( strlen( rls ) && rls !~ ": not found" && rls !~ ": Permission denied" && rls !~ ": cannot open " &&
      rls !~ "No such file or directory" && rls !~ "command not found" )
    _unknown_os_info += '/VERSION: ' + rls + '\n\n';
}

if( "Syntax Error: unexpected argument" >< rls ) {
  rls = ssh_cmd( socket:sock, cmd:'run util bash -c "cat /VERSION"', nosh:TRUE, nosu:TRUE );
  if( "BIG-" >< rls || "Product: EM" >< rls ) {
    set_kb_item( name:"f5/shell_is_tmsh", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  }
}

if( "BIG-IP" >< rls ) {
  set_kb_item( name:"f5/big_ip/lsc", value:TRUE ); # gb_f5_big_iq_ssh_login_detect.nasl
  set_kb_item( name:"f5/big_ip/VERSION_RAW", value:rls );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( "BIG-IQ" >< rls ) {
  set_kb_item( name:"f5/big_iq/lsc", value:TRUE ); # gb_f5_big_iq_version.nasl
  set_kb_item( name:"f5/big_iq/VERSION_RAW", value:rls );
  set_kb_item( name:"f5/big_iq/ssh-login/port", value:port );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( "Product: EM" >< rls && "BaseBuild" >< rls ) {
  set_kb_item( name:"f5/f5_enterprise_manager/lsc", value:TRUE ); # gb_f5_enterprise_manager_version.nasl
  set_kb_item( name:"f5/f5_enterprise_manager/VERSION_RAW", value:rls );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/meg-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/meg-release: ' + rls + '\n\n';
}

if( rls =~ "^McAfee" ) {
  set_kb_item( name:"mcafee/OS", value:TRUE ); # gb_mcafee_*_version.nasl
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/esrs-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/esrs-release: ' + rls + '\n\n';
}

if( chomp( rls ) =~ "^[0-9]+\.[0-9]+\.[0-9]$" ) {
  set_kb_item( name:"ems/esrs/rls", value:rls );
  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/NAS_CFG/config.xml", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/NAS_CFG/config.xml (truncated): ' + substr( rls, 0, 300 ) + '\n\n';
}

# <config>
#       *snip*
#       <hw_ver>MyCloudEX2Ultra</hw_ver>
# or:
# <config>
#       *snip*
#       <hw_ver>WDMyCloudMirror</hw_ver>
if( rls =~ "<hw_ver>(WD)?MyCloud.*</hw_ver>" ) {
  set_kb_item( name:"wd-mycloud/ssh-login/" + port + "/cfg_file", value:rls );
  set_kb_item( name:"wd-mycloud/ssh-login/port", value:port );
  set_kb_item( name:"wd-mycloud/ssh-login/cfg_file", value:TRUE );
  exit( 0 );
}

if( ! is_pfsense ) {
  # nb: We're using /etc/oracle-release because /etc/redhat-release exists but includes e.g. the
  # following:
  #
  # Red Hat Enterprise Linux Server release 5.11 (Tikanga)
  #
  # Also note that in an early version of this check "rpm -qf /etc/redhat-release" was used but that
  # wasn't working on Oracle Linux 5 because it has the following:
  #
  # enterprise-release-5-11.0.3
  #
  # while newer Oracle Linux releases have:
  #
  # oraclelinux-release-6Server-10.0.2.x86_64
  #
  cmd = "cat /etc/oracle-release";

  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += cmd + ": " + rls + '\n\n';
}

# Oracle Linux Server release 8.5
# Oracle Linux Server release 7.9
# Oracle Linux Server release 6.10
# Oracle Linux Server release 5.11
if( rls =~ "Oracle Linux ([^ ]+ )?release" ) {

  oskey = "OracleLinux";
  oskey_notus = "Oracle Linux";
  cpe = "cpe:/o:oracle:linux";
  os = "Oracle Linux";
  concluded  = '\n  Used command: ' + cmd;
  concluded += '\n  Response:     ' + rls;

  set_kb_item( name:"ssh/login/oracle_linux", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_rpms( buf:buf, custom_key_name:"ssh/login/package_list_notus" ) )
        error = buf;
    }

  }

  vers = eregmatch( pattern:"Oracle Linux ([^ ]+ )?release ([0-9]+)([0-9.]+)?", string:rls, icase:TRUE );
  if( vers[2] ) {

    version = vers[2];

    if( vers[3] )
      version += vers[3];

    cpe += ":" + version;

    # nb: Special handling as the Oracle / ELSA LSCs are using just the major release version in
    # their OS key checks (e.g. OracleLinux7). This applies to Notus as well (e.g. "Oracle Linux 8")
    oskey += vers[2];
    oskey_notus += " " + vers[2];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + version, rpm_access_error:error ) );
    os_register_and_report( os:os, version:version, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );
  set_kb_item( name:"ssh/login/release_notus", value:oskey_notus );

  exit( 0 );
}

if( ! is_pfsense ) {
  # Ok...let's first check if this is a RedHat/Fedora Core/Mandrake release
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/redhat-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/redhat-release: ' + rls + '\n\n';
}

if( "Space release " >< rls ) {
  set_kb_item( name:"junos/space", value:rls );
  exit( 0 );
}

if( "IWSVA release" >< rls ) {
  system = ssh_cmd( socket:sock, cmd:'/usr/bin/clish -c "show system version"', nosh:TRUE, nosu:TRUE, pty:FALSE );
  if( "Operating System" >< system && "IWSVA" >< system ) {
    set_kb_item( name:"IWSVA/ssh-login/port", value:port );
    set_kb_item( name:"IWSVA/system", value:system );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

if( "IMSVA release" >< rls ) {
  system = ssh_cmd( socket:sock, cmd:'/usr/bin/clish -c "show module IMSVA version"', nosh:TRUE, nosu:TRUE, pty:FALSE );
  if( system =~ "IMSVA [0-9.]+-Build_Linux_[0-9]+"  ) {
    set_kb_item( name:"IMSVA/ssh-login/port", value:port );
    set_kb_item( name:"IMSVA/system", value:system );
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    exit( 0 );
  }
}

if( rls =~ "^(XenServer|Citrix Hypervisor) release" ) {
  set_kb_item( name:"xenserver/installed", value:TRUE ); # gb_xenserver_version.nasl
  exit( 0 );
}

if( rls =~ "^McAfee"  ) {
  set_kb_item( name:"mcafee/OS", value:TRUE ); # gb_mcafee_*_version.nasl
  exit( 0 );
}

if( rls =~ "red hat linux release" ) {
  oskey = "RH";
  cpe = "cpe:/o:redhat:linux";

  set_kb_item( name:"ssh/login/redhat_linux", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"red hat linux release ([0-9.]+)", string:rls, icase:TRUE );
  if( vers[1] ) {
    cpe += ":" + vers[1];
    oskey += vers[1];
    os_register_and_report( os:rls, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    os_register_and_report( os:rls, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  log_message( port:port, data:create_lsc_os_detection_report( detect_text:rls, rpm_access_error:error ) );
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

if( rls =~ "fedora" && rls =~ "release" ) {
  oskey = "FC";
  if( rls =~ "fedora core" ) {
    cpe = "cpe:/o:fedoraproject:fedora_core";
    set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
    os = "Fedora Core";
  } else {
    cpe = "cpe:/o:fedoraproject:fedora";
    set_kb_item( name:"ssh/login/fedora", value:TRUE );
    os = "Fedora";
  }

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"fedora( core | )release ([0-9]+)", string:rls, icase:TRUE );
  if( vers[2] ) {
    cpe += ":" + vers[2];
    oskey += vers[2];
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " release " + vers[2], rpm_access_error:error ) );
    os_register_and_report( os:os, version:vers[2], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

# Red Hat Enterprise Linux ES release 2.1 (Panama)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 1)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 2)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 3)
# Red Hat Enterprise Linux Desktop release 3.90
# Red Hat Enterprise Linux Server release 5.11 (Tikanga)
# Red Hat Enterprise Linux release 8.6 (Ootpa)
if( rls =~ "red hat enterprise linux.*release" ) {
  oskey = "RHENT_";
  cpe = "cpe:/o:redhat:enterprise_linux";

  set_kb_item( name:"ssh/login/rhel", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"red hat enterprise linux.*release (2\.1|[0-9]+)", string:rls, icase:TRUE );
  if( vers[1] ) {
    cpe += ":" + vers[1];
    oskey += vers[1];
    os_register_and_report( os:rls, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    os_register_and_report( os:rls, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  log_message( port:port, data:create_lsc_os_detection_report( detect_text:rls, rpm_access_error:error ) );
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

if( rls =~ "mandriva" || rls =~ "mandrake" ) {

  oskey = "MNDK_";
  if( rls =~ "mandriva linux enterprise server" ) {
    cpe = "cpe:/o:mandriva:enterprise_server";
    os = "Mandriva Linux Enterprise Server";
  } else if( rls =~ "mandriva" ) {
    cpe = "cpe:/o:mandriva:linux";
    os = "Mandriva Linux";
  } else {
    cpe = "cpe:/o:mandrakesoft:mandrake_linux";
    os = "Mandrake Linux";
  }

  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"mandr(iva|ake).*inux ?(enterprise server)? release ([0-9.]+)", string:rls, icase:TRUE );
  if( vers[3] ) {
    cpe += ":" + vers[3];
    if( vers[2] ) {
      oskey += "mes" + vers[3];
    } else {
      oskey += vers[3];
    }
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " release " + vers[3], rpm_access_error:error ) );
    os_register_and_report( os:os, version:vers[3], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
    # nb: Additionally need to register Mandriva Enterprise Server 5 if a version of 5.0 has been detected
    if( vers[2] && vers[3] == "5.0" ) {
      os_register_and_report( os:os, version:"5", cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
    }
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

if( rls =~ "mageia release" ) {

  oskey = "MAGEIA";
  cpe = "cpe:/o:mageia:linux";
  os = "Mageia";
  oskey_notus = "Mageia";

  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_rpms( buf:buf, custom_key_name:"ssh/login/package_list_notus" ) )
        error = buf;
    }
  }

  vers = eregmatch( pattern:"mageia release ([0-9.]+)", string:rls, icase:TRUE );
  if( vers[1] ) {
    cpe += ":" + vers[1];
    oskey += vers[1];
    oskey_notus += " " + vers[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " release " + vers[1], rpm_access_error:error ) );
    os_register_and_report( os:os, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );
  set_kb_item( name:"ssh/login/release_notus", value:oskey_notus );

  exit( 0 );
}

# Cisco UCS Director is CentOS based which will be seen as such if not logged in with the shelladmin account
# so we want to catch this before the actual CentOS detection
if( rls =~ "centos( linux)? release" ) {
  # UCS Director version can be accessed over /opt/infra/sysmgr/version.sh
  buf = ssh_cmd( socket:sock, cmd:"/opt/infra/sysmgr/version.sh" );
  if( "Cisco UCS Director Platform" >< buf ) {
    set_kb_item( name:"cisco_ucs_director/ssh_login/port", value:port );
    set_kb_item( name:"cisco_ucs_director/show_version", value:buf );
    exit( 0 );
  }
}

# Ok...also using /etc/redhat-release is CentOS...let's try them now
# We'll stay with major release # checking unless we find out we need to do
# otherwise.
#CentOS Stream release 8
#CentOS Linux release 8.2.2004 (Core)
#CentOS Linux release 7.8.2003 (Core)
#CentOS release 4.0 (Final)
#CentOS release 4.1 (Final)
#CentOS release 3.4 (final)

if( rls =~ "centos( (linux|stream))? release" ) {

  oskey = "CentOS";
  cpe = "cpe:/o:centos:centos";
  os = "CentOS";

  set_kb_item( name:"ssh/login/centos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"centos( (linux|stream))? release ([0-9]+)", string:rls, icase:TRUE );
  if( vers[3] ) {
    major_vers = vers[3];

    # nb: Special handling for the plain CentOS 8 (already EOL) and the Stream 8 variant (not EOL
    # yet) so avoid wrong EOL reporting.
    if( vers[2] && vers[2] =~ "^stream$" ) {
      os  += " Stream";
      cpe += "_stream";
    }

    cpe += ":" + major_vers;
    oskey += major_vers;

    if( version_is_greater_equal( version:major_vers, test_version:"8" ) )
      no_lsc_support = TRUE;

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " release " + major_vers, rpm_access_error:error, no_lsc_support:no_lsc_support ) );
    os_register_and_report( os:os, version:major_vers, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

if( ! is_pfsense ) {
  # nb: Keep above the Ubuntu check below so that we're not exiting early without setting the OpenVPN AS infos.
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/issue", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/issue: ' + rls + '\n\n';
}

match = eregmatch( pattern:"^Univention (Managed Client|Mobile Client|DC Master|DC Backup|DC Slave|Memberserver|Corporate Server) ([2][.][0-4])-[0-9]+-[0-9]+", string:rls );
if( ! isnull( match ) ) {
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=600 dpkg -l" );
  if( ! isnull( buf ) ) {
    register_packages( buf:buf );
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:match[0] ) );
    set_kb_item( name:"ssh/login/release", value:"UCS" + match[2] );

    os_register_and_report( os:"Univention Corporate Server", version:match[2], cpe:"cpe:/o:univention:univention_corporate_server", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
}

if( "OpenVPN Access Server Appliance" >< rls ) {
  # nb: Used in gb_openvpn_access_server_ssh_login_detect.nasl
  set_kb_item( name:"ssh/login/openvpn_as/etc_issue", value:rls );
  set_kb_item( name:"openvpn/ssh-login/port", value:port );
}

# nb: See gsf/gb_flir_neco_platform_ssh_login_detect.nasl for examples
if( rls =~ "^neco_v[0-9.]+" ) {
  set_kb_item( name:"ssh/login/flir/neco_platform/" + port + "/etc_issue", value:chomp( rls ) );
  set_kb_item( name:"ssh/login/flir/neco_platform/port", value:port );
  set_kb_item( name:"ssh/login/flir/neco_platform/detected", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( ! is_pfsense ) {
  # Hmmm...is it Ubuntu?
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/lsb-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/lsb-release: ' + rls + '\n\n';
}

if( rls =~ "distrib_id=ubuntu" && rls =~ "distrib_release=" ) {

  os = "Ubuntu";
  oskey = "UBUNTU";
  oskey_notus = "Ubuntu ";
  cpe = "cpe:/o:canonical:ubuntu_linux";

  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );

  vers = eregmatch( pattern:"distrib_release=([0-9]+)\.([0-9]+)\.?([0-9]+)?", string:rls, icase:TRUE );
  if( vers[1] && vers[2] ) {

    # Since Ubuntu 19.04 / dpkg version 1.19.1, the dpkg -l only returns a few packages because the user
    # needs to scroll. See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=909754 for more background info.
    # Using the --no-pager option (available since dpkg 1.19.2) solves this problem.
    if( vers[1] =~ "^[0-9]+" && version_is_greater_equal( version:vers[1], test_version:"19" ) )
      buf = ssh_cmd( socket:sock, cmd:"dpkg --no-pager -l");
    else
      buf = ssh_cmd( socket:sock, cmd:"COLUMNS=600 dpkg -l" );

    if( buf )
      register_packages( buf:buf );

    buf = ssh_cmd( socket:sock, cmd:"dpkg-query -W -f=\$\{Package\}-\$\{Version\}'\n'" );
    if( buf )
      set_kb_item( name:"ssh/login/package_list_notus", value:buf );

    if( vers[3] )
      version = vers[1] + "." + vers[2] + "." + vers[3];
    else
      version = vers[1] + "." + vers[2];

    oskey_notus += version;

    if( vers[1] % 2 == 0 && vers[2] =~ "0[46]") {
      lts = " LTS";
      oskey += version + lts;
      cpe += ":" + version + ":-:lts";
    } else {
      oskey += version;
      cpe += ":" + version;
    }

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + version + lts ) );
    os_register_and_report( os:os, version:version + lts, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  set_kb_item( name:"ssh/login/release", value:oskey );
  set_kb_item( name:"ssh/login/release_notus", value:oskey_notus );

  exit( 0 );
}

if( rls =~ 'DISTRIB_ID=("|\')?Univention("|\')?' ) {

  ucs_release = eregmatch( string:rls, pattern:'DISTRIB_RELEASE="([1-9][0-9]*[.][0-9]+)-([0-9]+) errata([0-9]+)[^"]*"' );

  if( ! isnull( ucs_release[1] ) )
    set_kb_item( name:"ucs/version", value:ucs_release[1] );

  if( ! isnull( ucs_release[2] ) )
    set_kb_item( name:"ucs/patch", value:ucs_release[2] );

  if( ! isnull( ucs_release[3] ) )
    set_kb_item( name:"ucs/errata", value:ucs_release[3] );

  ucs_description = eregmatch( string:rls, pattern:'DISTRIB_DESCRIPTION="([^"]*)"' );

  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=600 dpkg -l" );
  if( buf )
    register_packages( buf:buf );

  if( ! isnull( ucs_release ) && ! isnull( ucs_description ) ) {

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:ucs_description[1] ) );

    set_kb_item( name:"ssh/login/release", value:"UCS" + ucs_release[1] );

    os_register_and_report( os:ucs_description[1], version:ucs_release[1], cpe:"cpe:/o:univention:univention_corporate_server", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_unknown_banner( banner:'Unknown Univention release.\n\ncat /etc/lsb-release:\n\n' + rls, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }
  exit( 0 );
}

if( rls =~ "^DISTRIB_ID=Sophos Firewall" ) {
  set_kb_item( name:"ssh/login/sophos/firewall", value:TRUE );
  set_kb_item( name:"sophos/xg_firewall/ssh-login/port", value:port );

  vers = ssh_cmd( socket:sock, cmd:"cat /etc/version", return_errors:FALSE );
  if( vers )
    set_kb_item( name:"sophos/xg_firewall/ssh-login/" + port + "/etc_version", value:vers );

   exit( 0 );
}

if( ! is_pfsense ) {
  # How about Conectiva Linux?
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/conectiva-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/conectiva-release: ' + rls + '\n\n';
}

if( rls =~ "conectiva linux" ) {

  oskey = "CL";
  cpe = "cpe:/o:conectiva:linux";
  os = "Conectiva Linux";

  set_kb_item( name:"ssh/login/conectiva", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"conectiva linux ([0-9.]+)", string:rls, icase:TRUE );
  if( vers[1] ) {
    cpe += ":" + vers[1];
    oskey += vers[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + vers[1], rpm_access_error:error ) );
    os_register_and_report( os:os, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

# How about Turbolinux?
# Turbolinux signatures:
# release 6.0 WorkStation (Shiga)       -- Unsupported
# TurboLinux release 6.1 Server (Naha)  -- Unsupported
# Turbolinux Server 6.5 (Jupiter)       -- Unsupported
# Turbolinux Server 7.0 (Esprit)
# Turbolinux Workstation 7.0 (Monza)
# Turbolinux Server 8.0 (Viper)
# Turbolinux Workstation 8.0 (SilverStone)
# Turbolinux Server 10.0 (Celica)
# Turbolinux Desktop 10.0 (Suzuka)
# -- Need:
#- Turbolinux Appliance Server 1.0 Hosting Edition
#- Turbolinux Appliance Server 1.0 Workgroup Edition
#- Turbolinux Home
#- Turbolinux 10 F...

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/turbolinux-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/turbolinux-release: ' + rls + '\n\n';
}

if( rls =~ "turbolinux (workstation|server|desktop)" ) {

  if( rls =~ "workstation" ) {
    oskey = "TLWS";
    cpe = "cpe:/o:turbolinux:turbolinux_workstation";
    os = "Turbolinux Workstation";
  } else if( rls =~ "server" ) {
    oskey = "TLS";
    cpe = "cpe:/o:turbolinux:turbolinux_server";
    os = "Turbolinux Server";
  } else {
    oskey = "TLDT";
    cpe = "cpe:/o:turbolinux:turbolinux_desktop";
    os = "Turbolinux Desktop";
  }

  set_kb_item( name:"ssh/login/turbolinux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"turbolinux.*([0-9.]+)", string:rls, icase:TRUE );
  if( vers[1] ) {
    cpe += ":" + vers[1];
    oskey += vers[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + vers[1], rpm_access_error:error, no_lsc_support:TRUE ) );
    os_register_and_report( os:os, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error, no_lsc_support:TRUE ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

if( rls =~ "turbolinux" ) {
  log_message( port:port, data:"We have detected you are running a version of Turbolinux currently not supported. Please report the following banner: " + rls );
  exit( 0 );
}

if( ! is_pfsense ) {
  # Hmmm...is it Debian?
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/debian_version", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/debian_version: ' + rls + '\n\n';
}

# nb: At least Ubuntu 18.10 has "buster/sid" in debian_version so keep this in mind
# if Ubuntu is wrongly detected and keep the Ubuntu pattern above the Debian ones.
if( rls =~ "^[0-9]+[0-9.]+" || rls =~ "buster/sid" || rls =~ "bullseye/sid" ) {

  rls   = chomp( rls );
  cpe   = "cpe:/o:debian:debian_linux";
  oskey = "DEB";
  oskey_notus = "Debian ";

  set_kb_item( name:"ssh/login/debian_linux", value:TRUE );

  # Since Debian 10 (Buster) / dpkg version 1.19.1, the dpkg -l only returns a few packages because the user
  # needs to scroll. See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=909754 for more background info.
  # Adding --no-pager option (available since dpkg 1.19.2) solves this problem.
  if( ( rls =~ "^[0-9]+[0-9.]+" && version_is_greater_equal( version:rls, test_version:"10" ) ) || rls =~ "buster/sid" || rls =~ "bullseye/sid" ) {
    buf = ssh_cmd( socket:sock, cmd:"dpkg --no-pager -l" );
  } else {
    buf = ssh_cmd( socket:sock, cmd:"COLUMNS=600 dpkg -l" );
  }

  if( buf ) {
    register_packages( buf:buf );

    # Proxmox Virtual Environment (VE, PVE) only runs on Debian, this is for gsf/gb_proxmox_ve_ssh_login_detect.nasl
    if( concl = egrep( string:buf, pattern:"^ii.+(pve-manager|Proxmox Virtual Environment Management Tools)", icase:FALSE ) ) {
      concl = chomp( concl );
      # nb: See reason in register_packages().
      concl = ereg_replace( string:concl, pattern:" {3,}", replace:"  " );
      set_kb_item( name:"ssh/login/proxmox/ve/detected", value:TRUE );
      set_kb_item( name:"ssh/login/proxmox/ve/port", value:port );
      set_kb_item( name:"ssh/login/proxmox/ve/" + port + "/concluded", value:concl );
    }
  }

  log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Debian GNU/Linux " + rls ) );

  vers = eregmatch( pattern:"^([0-9]+)([0-9.]+)", string:rls );
  if( vers[1] ) {
    cpe   += ":" + vers[1];
    oskey += vers[1]; # nb: We only want to save the "major" release like 6, 7 and so on in ssh/login/release...
    oskey_notus += vers[1]; # e.g. Debian 8
  }

  if( vers[2] ) {
    cpe += vers[2];
    if( vers[1] =~ "^[1-3]$" ) {
      oskey += vers[2]; # nb: but the older releases needs the second digit as well...
      oskey_notus += vers[2]; # e.g. Debian 3.1
    }
  }

  if( ! vers ) {
    if( rls =~ "buster/sid" ) {
      cpe   += ":10.0";
      oskey += "10";
      oskey_notus += "10";
    } else if( rls =~ "bullseye/sid" ) {
      cpe   += ":11.0";
      oskey += "11";
      oskey_notus += "11";
    }
  }

  # Gather package information for Debian in Notus
  buf = ssh_cmd( socket:sock, cmd:"dpkg-query -W -f=\$\{Package\}-\$\{Version\}'\n'" );
  if( buf )
    set_kb_item( name:"ssh/login/package_list_notus", value:buf );

  set_kb_item( name:"ssh/login/release", value:oskey );
  set_kb_item( name:"ssh/login/release_notus", value:oskey_notus );
  os_register_and_report( os:"Debian GNU/Linux", version:rls, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );

  exit( 0 );
}

if( ! is_pfsense ) {
  # How about Slackware?
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/slackware-version", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/slackware-version: ' + rls + '\n\n';
}

# Slackware 13.0.0.0.0
# Slackware 13.37.0
# Slackware 14.0
# Slackware 14.1
# Slackware 14.2
# Slackware 15.0
# nb: The following is from Slackware current:
# Slackware 15.0+
if( "Slackware " >< rls ) {
  oskey = "SLK";
  oskey_notus = "Slackware";
  cpe = "cpe:/o:slackware:slackware_linux";
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls -1 /var/log/packages" );
  if( buf ) {
    set_kb_item( name:"ssh/login/slackpack", value:buf );
    set_kb_item( name:"ssh/login/package_list_notus", value:buf );
  }

  vers = eregmatch( pattern:"Slackware (([0-9]+)\.([0-9]+))(\+$)?", string:rls, icase:FALSE );

  if( vers[1] ) {
    # If the release ends in a "+", the host is running Slackware current.
    if( vers[4] ) {
      release = "current";
    } else {
      release = vers[1];
    }
    # Even if the release is current, the CPE will be for the latest major release
    cpe += ":" + vers[1];
    oskey += release;
    oskey_notus += " " + release;
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Slackware " + release ) );
    os_register_and_report( os:"Slackware", version:release, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Slackware" ) );
    os_register_and_report( os:"Slackware", cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );
  set_kb_item( name:"ssh/login/release_notus", value:oskey_notus );

  exit( 0 );
}

if( ! is_pfsense ) {
  # The way ahead looks Rocky...
  cmd = "cat /etc/rocky-release";
  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );
  if( strlen( rls ) )
    _unknown_os_info += cmd + ": " + rls + '\n\n';
}

# Rocky Linux release 8.4 (Green Obsidian)
# Rocky Linux release 8.5 (Green Obsidian)
if( rls =~ "Rocky Linux release" ) {

  oskey = "RL";
  os = "Rocky Linux";
  notusoskey = "Rocky Linux";
  concluded  = '\n  Used command: ' + cmd;
  concluded += '\n  Response:     ' + rls;

  # Used by the project in /etc/rocky-release but probably should be updated if a different CPE is
  # used within the NVD.
  cpe = "cpe:/o:rocky:rocky";

  set_kb_item( name:"ssh/login/rocky_linux", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;

    # Notus requires a more verbose package name output
    # and also requires it to be written to its own package_list key
    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_rpms( buf:buf, custom_key_name:"ssh/login/package_list_notus" ) )
        error = buf;
    }
  }

  vers = eregmatch( pattern:"Rocky Linux release ([0-9]+)([0-9.]+)?", string:rls, icase:TRUE );
  if( vers[1] ) {

    version = vers[1];

    if( vers[2] )
      version += vers[2];

    cpe += ":" + version;

    # As of original implementation, Rocky Linux reports as version '8.4' or '8.5' in
    # '/etc/rocky-release'. Their advisories currently only report product 'Rocky Linux 8' so we
    # will stick with the major version in the oskey like e.g. RL8 (instead of RL8.5) for now.
    oskey += vers[1];
    # Notus scanner requires the release_notus key set further down, which needs to be exactly
    # matched against the product_name in notus product files,
    # which for Rocky requires "Rocky Linux <release>"
    notusoskey = os + " " + vers[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + version, rpm_access_error:error ) );
    os_register_and_report( os:os, version:version, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  set_kb_item( name:"ssh/login/release", value:oskey );
  # Notus standardized release key
  set_kb_item( name:"ssh/login/release_notus", value:notusoskey );

  exit( 0 );
}

if( ! is_pfsense ) {
  # Alma take a break here...
  cmd = "cat /etc/almalinux-release";
  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );
  if( strlen( rls ) )
    _unknown_os_info += cmd + ": " + rls + '\n\n';
}

# AlmaLinux release 8.5 (Arctic Sphynx)
# AlmaLinux release 8.6 (Sky Tiger)
# AlmaLinux release 9.0 (Emerald Puma)
if( rls =~ "AlmaLinux release" ) {

  oskey = "AL";
  os = "AlmaLinux";
  notusoskey = "AlmaLinux";
  concluded  = '\n  Used command: ' + cmd;
  concluded += '\n  Response:     ' + rls;

  # Used by the project in /etc/os-release but probably should be updated if a different CPE is
  # used within the NVD.
  cpe = "cpe:/o:almalinux:almalinux";

  set_kb_item( name:"ssh/login/alma_linux", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;

    # Notus requires a more verbose package name output
    # and also requires it to be written to its own package_list key
    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_rpms( buf:buf, custom_key_name:"ssh/login/package_list_notus" ) )
        error = buf;
    }
  }

  vers = eregmatch( pattern:"AlmaLinux release ([0-9]+)([0-9.]+)?", string:rls, icase:TRUE );
  if( vers[1] ) {

    version = vers[1];

    if( vers[2] )
      version += vers[2];

    cpe += ":" + version;

    # As of original implementation, AlmaLinux reports as version '8.4' or '8.5' in
    # '/etc/almalinux-release'. Their advisories currently only report product 'AlmaLinux 8' so we
    # will stick with the major version in the oskey like e.g. AL8 (instead of AL8.5) for now.
    oskey += vers[1];
    # Notus scanner requires the release_notus key set further down, which needs to be exactly
    # matched against the product_name in notus product files,
    # which for Alma requires "AlmaLinux <release>"
    notusoskey = os + " " + vers[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + version, rpm_access_error:error ) );
    os_register_and_report( os:os, version:version, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  set_kb_item( name:"ssh/login/release", value:oskey );
  # Notus standardized release key
  set_kb_item( name:"ssh/login/release_notus", value:notusoskey );

  exit( 0 );
}

if( ! is_pfsense ) {
  # How about SuSe? and openSUSE?
  # https://en.wikipedia.org/wiki/SUSE_Linux_distributions
  #
  # https://www.freedesktop.org/software/systemd/man/os-release.html
  # nb: /etc/os-release is in most cases a symlink to /usr/lib/os-release as described
  # in the specs but we're still trying both to be sure to catch all possible cases.
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/os-release", return_errors:FALSE );

  if( strlen( rls ) ) {
    _unknown_os_info += '/etc/os-release: ' + rls + '\n\n';
    suse_os_rls = rls; # nb: Used later for SLES/SLED 15+
  }

  if( ! rls ) {
    rls = ssh_cmd( socket:sock, cmd:"cat /usr/lib/os-release", return_errors:FALSE );

    if( strlen( rls ) ) {
      _unknown_os_info += '/usr/lib/os-release: ' + rls + '\n\n';
      suse_os_rls = rls; # nb: Used later for SLES/SLED 15+
    }
  }
}

if( rls =~ "(open)?suse( leap| linux)?" && rls !~ "enterprise" ) {

  if( rls =~ "opensuse leap" ) {
    oskey = "openSUSELeap";
    cpe = "cpe:/o:opensuse:leap";
    os = "openSUSE Leap";
  } else if( rls =~ "opensuse" ) {
    oskey = "openSUSE";
    cpe = "cpe:/o:novell:opensuse";
    os = "openSUSE";
  } else {
    oskey = "SUSE";
    cpe = "cpe:/o:novell:suse_linux";
    os = "SuSE Linux";
  }

  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"(open)?suse (leap |linux )?([0-9.]+)", string:rls, icase:TRUE );
  if( vers[3] ) {
    cpe += ":" + vers[3];
    oskey += vers[3];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + vers[3], rpm_access_error:error ) );
    os_register_and_report( os:os, version:vers[3], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

# nb: Arch Linux is a rolling release so there is no "real" version
if( 'NAME="Arch Linux"' >< rls ) {
  set_kb_item( name:"ssh/login/arch_linux", value:TRUE );
  log_message( port:port, data:create_lsc_os_detection_report( no_lsc_support:TRUE, detect_text:"Arch Linux" ) );

  set_kb_item( name:"ssh/login/release", value:"ArchLinux" );

  os_register_and_report( os:"Arch Linux", cpe:"cpe:/o:archlinux:arch_linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "NAME=NixOS" >< rls || "ID=nixos" >< rls ) {
  set_kb_item( name:"ssh/login/nixos", value:TRUE );
  # e.g. VERSION_ID="18.09pre145524.2a8a5533d18"
  version = eregmatch( pattern:'VERSION_ID="([^"]+)"', string:rls );
  if( version[1] ) {
    log_message( port:port, data:create_lsc_os_detection_report( no_lsc_support:TRUE, detect_text:"NixOS " + version[1] ) );
    os_register_and_report( os:"NixOS", version:version[1], cpe:"cpe:/o:nixos_project:nixos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( no_lsc_support:TRUE, detect_text:"an unknown NixOS release" ) );
    os_register_and_report( os:"NixOS", cpe:"cpe:/o:nixos_project:nixos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    os_register_unknown_banner( banner:'Unknown NixOS release.\n\ncat /etc/os-release: ' + rls, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }
  exit( 0 );
}

if( 'NAME="VMware Photon OS"' >< rls ) {
  set_kb_item( name:"ssh/login/photonos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"cat /etc/photon-release", return_errors:FALSE, force_reconnect:TRUE );
  # VMware Photon OS 2.0
  # PHOTON_BUILD_NUMBER=0922243
  version = eregmatch( pattern:"VMware Photon OS ([0-9.]+)", string:buf );
  if( ! isnull( version[1] ) ) {
    build = "unknown";
    bld = eregmatch( pattern:"PHOTON_BUILD_NUMBER=([0-9]+)", string:buf );
    if( ! isnull( bld[1] ) ) {
      build = bld[1];
      set_kb_item( name:"ssh/login/photonos/build", value:build );
    }
    log_message( port:port, data:create_lsc_os_detection_report( no_lsc_support:TRUE, detect_text:"VMware Photon OS " + version[1] + " Build: " + build ) );
    os_register_and_report( os:"VMware Photon OS", version:version[1], cpe:"cpe:/o:vmware:photonos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( no_lsc_support:TRUE, detect_text:"an unknown VMware Photon OS release" ) );
    os_register_and_report( os:"VMware Photon OS", cpe:"cpe:/o:vmware:photonos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    os_register_unknown_banner( banner:'Unknown VMware Photon OS release.\n\ncat /etc/photon-release: ' + buf, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }
  exit( 0 );
}

# nb: See gsf/gb_flir_neco_platform_ssh_login_detect.nasl for examples
if( rls =~ "((ID|NAME|VERSION)=flir|PRETTY_NAME=FLIR Systems platform)" && "neco" >< rls ) {
  set_kb_item( name:"ssh/login/flir/neco_platform/" + port + "/etc_os-release", value:chomp( rls ) );
  set_kb_item( name:"ssh/login/flir/neco_platform/port", value:port );
  set_kb_item( name:"ssh/login/flir/neco_platform/detected", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( rls =~ 'NAME\\s*=\\s*"OpenWrt"' && "OPENWRT_DEVICE_" >< rls ) {
  set_kb_item( name:"ssh/login/openwrt/" + port + "/etc_os-release", value:chomp( rls ) );
  set_kb_item( name:"ssh/login/openwrt/port", value:port );
  set_kb_item( name:"ssh/login/openwrt/detected", value:TRUE );
  replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  exit( 0 );
}

if( ! is_pfsense ) {
  # nb: In SLES12+ /etc/SuSE-release is deprecated in favor of /etc/os-release
  # and since SLES15 the file is gone.
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/SuSE-release", return_errors:FALSE );

  # For legacy hosts with e.g. SLES9 RC5, only /etc/SuSE-release is present and it can look like:
  # SUSE LINUX Enterprise Server 9 (x86_64)
  # VERSION = 9

  # For SLED9 32Bit from Novell, the same thing applies here:
  # Novell Linux Desktop 9 (i586)
  # VERSION = 9
  # RELEASE = 9

  if( strlen( rls ) )
    _unknown_os_info += '/etc/SuSE-release: ' + rls + '\n\n';
}

if( rls =~ "suse linux enterprise" || suse_os_rls =~ "suse linux enterprise" || rls =~ "novell linux " || suse_os_rls =~ "novell linux ") {
  # For SUSE Linux Enterprise Server/Desktop

  # Note: At this point, rls contains /etc/SuSE-release and suse_os_rls contains /etc/os-release

  type = "Server";

  # nb: To support both, /etc/SuSE-release for older releases and /etc/os-release for newer ones.
  # Very old versions don't have /etc/os-release, so they would use /etc/SuSE-release -> Our fallback
  if( suse_os_rls ) {
    # Using /etc/os-release
    rls = suse_os_rls;

    # e.g. PRETTY_NAME="SUSE Linux Enterprise Server 15 SP2"
    # NOTE: https://www.suse.com/support/kb/doc/?id=000019341
    # More examples: http://www.scalingbits.com/linux/identification

    # The pretty name also accounts for releases like:
    # SUSE Linux Enterprise Server for SAP 11 SP2
    pretty_name_match = eregmatch( pattern:'PRETTY_NAME="([^"]+)"', string:rls, icase:TRUE );
    if( pretty_name_match[1] ) {
      # SUSE Linux Enterprise Server for SAP 10 SP0
      # SUSE Linux Enterprise Desktop 12 SP0
      pretty_name = pretty_name_match[1];
      # e.g. SUSE Linux Enterprise Server for SAP 11-SP2
      notus_os_release = ereg_replace( string:pretty_name, pattern:"\s(SP[0-9]+)", replace:"-\1" );
      notus_os_release = ereg_replace( string:notus_os_release, pattern:"-SP0", replace:"" );

      # This pattern also accounts for different variations of SLES as well as SLED
      patch_vers_match = eregmatch( pattern:"SUSE Linux Enterprise ([a-zA-Z ]+)([0-9]+)( SP([0-9]+))?", string:pretty_name, icase:TRUE );
      if( patch_vers_match[2] )
        version = patch_vers_match[2];
      else
        version = "";

      if( patch_vers_match[4] )
        patchlevel = patch_vers_match[4];
      else
        patchlevel = "0";

      if( pretty_name =~ "Enterprise Desktop" ) {
        type = "Desktop";
      }
    }
  } else {
    # Using /etc/SuSE-release -> Fallback for older releases

    patch_match = eregmatch( pattern:"PATCHLEVEL = ([0-9]+)", string:rls, icase:TRUE );
    if( patch_match[1] )
      patchlevel = patch_match[1];
    else
      patchlevel = "0";

    version_match = eregmatch( pattern:"VERSION = ([0-9]+)", string:rls, icase:TRUE );
    if( version_match[1] )
      version = version_match[1];
    else
      version = "";

    # This pattern also accounts for variations of SLES like "SUSE Linux Enterprise Server for SAP"
    # It also covers SLED as well as Novell Linux Desktop
    os_name_match = eregmatch( pattern:"(SUSE Linux Enterprise ([a-zA-Z ]+)|Novell Linux Desktop)", string:rls, icase:TRUE );
    if( os_name_match[1] ) {
      # e.g. "SUSE Linux Enterprise Server " or "SUSE Linux Enterprise Server for SAP "
      # but also e.g. "SUSE LINUX Enterprise Server 9 " or "Novell Linux Desktop 9"
      if( os_name_match[1] =~ "Enterprise Desktop" ) {
        type = "Desktop";
        notus_os_release = "SUSE Linux Enterprise Desktop ";
      } else {
        notus_os_release = "SUSE Linux Enterprise Server ";
      }

      if( version && patchlevel == "0" )
        notus_os_release += version;
      else if( version && patchlevel )
        notus_os_release += version + "-SP" + patchlevel;
      # Remove possible trailing space
      notus_os_release = chomp(notus_os_release);
    }
  }

  if( type == "Server" ) {
    oskey = "SLES";
    cpe = "cpe:/o:suse:linux_enterprise_server";
    os = "SUSE Linux Enterprise Server";
    set_kb_item( name:"ssh/login/suse_sles", value:TRUE );
  } else {
    oskey = "SLED";
    cpe = "cpe:/o:suse:linux_enterprise_desktop";
    os = "SUSE Linux Enterprise Desktop";
  }

  if( !isnull(notus_os_release) && notus_os_release )
    set_kb_item( name:"ssh/login/release_notus", value:notus_os_release );

  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
    else {
      # Collect the RPMs in a different format for the Notus scanner
      buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
      if( buf ) {
        if( ! register_rpms( buf:buf, custom_key_name:"ssh/login/package_list_notus" ) )
          error = buf;
      }
    }
  }

  if( version ) {
    if( os == "SUSE Linux Enterprise Server" ) {
      # nb: Discard the SP info for SLES 11 SP0 and below
      if( version < "11" || ( version == "11" && patchlevel == "0" ) ) {
        oskey += version + ".0";
        cpe += ":" + version;
      } else {
        oskey += version + ".0SP" + patchlevel;
        cpe += ":" + version + ":sp" + patchlevel;
      }

      log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    } else {
      # SUSE Linux Enterprise Desktop

      oskey += version + ".0SP" + patchlevel;
      cpe += ":" + version + ":sp" + patchlevel;

      log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + version + " SP" + patchlevel, rpm_access_error:error ) );
    }
    os_register_and_report( os:os, version:version, patch:"SP" + patchlevel, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}

if( ! is_pfsense ) {
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/release: ' + rls + '\n\n';
}

if( "Endian Firewall " >< rls ) {
  set_kb_item( name:"endian_firewall/release", value:rls );
  exit( 0 );
}

if( rls = egrep( string:rls, pattern:"OpenIndiana ", icase:FALSE ) ) {

  rls = chomp( rls );
  concl = "/etc/release: " + rls;
  set_kb_item( name:"openindiana/release", value:rls );

  report = "OpenIndiana";
  openi_cpe = "cpe:/o:openindiana:openindiana";

  # e.g.:
  #              OpenIndiana Hipster 2018.04 (powered by illumos)
  #              OpenIndiana Hipster 2019.04 (powered by illumos)
  # The tested 2014.x, 2015.x and 2016.x releases had this one:
  #              OpenIndiana Development oi_151.1.8 X86 (powered by illumos)
  if( " Development " >< rls ) {
    openi_version = eregmatch( pattern:"OpenIndiana Development oi_([0-9.]+)", string:rls );
    openi_cpe += "_development";
  } else if( " Hipster " >< rls ) {
    openi_version = eregmatch( pattern:"OpenIndiana Hipster ([0-9.]+)", string:rls );
    openi_cpe += "_hipster";
  } else {
    os_register_unknown_banner( banner:rls, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
    openi_cpe += "_unknown_release";
  }

  if( ! isnull( openi_version[1] ) ) {
    report += " " + openi_version[1];
    os_register_and_report( os:"OpenIndiana", version:openi_version[1], cpe:openi_cpe, banner_type:"SSH login", banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"OpenIndiana", cpe:openi_cpe, banner_type:"SSH login", banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  log_message( port:port, data:create_lsc_os_detection_report( no_lsc_support:TRUE, detect_text:report ) );

  # nb: SunOS will be caught later below
  is_openindiana = TRUE;
}

if( ! is_pfsense && ! is_openindiana ) {
  # How about Trustix?
  rls2 = ssh_cmd( socket:sock, cmd:"cat /etc/trustix-release", return_errors:FALSE );

  if( strlen( rls2 ) )
    _unknown_os_info += '/etc/trustix-release: ' + rls2 + '\n\n';
}

if( rls =~ "trustix secure linux release" ||
    rls2 =~ "trustix secure linux release" ) {

  oskey = "TSL";
  cpe = "cpe:/o:trustix:secure_linux";
  os = "Trustix";

  set_kb_item( name:"ssh/login/trustix", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"trustix secure linux release ([0-9.]+)", string:rls, icase:TRUE );
  if( vers[1] ) {
    cpe += ":" + vers[1];
    oskey += vers[1];

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + vers[1], rpm_access_error:error, no_lsc_support:TRUE ) );
    os_register_and_report( os:os, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error, no_lsc_support:TRUE ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}
# Missing Trustix e-2

if( ! is_pfsense && ! is_openindiana ) {
  # How about Gentoo? Note, just check that its ANY gentoo release, since the build
  # doesn't matter for purposes of checking package version numbers.
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/gentoo-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/gentoo-release: ' + rls + '\n\n';
}

if( "Gentoo" >< rls ) {
  set_kb_item( name:"ssh/login/gentoo", value:TRUE );
  set_kb_item( name:"ssh/login/release", value:"GENTOO" );
  buf = ssh_cmd( socket:sock, cmd:'find /var/db/pkg -mindepth 2 -maxdepth 2 -printf "%P\\n"' );
  set_kb_item( name:"ssh/login/pkg", value:buf );
  # Determine the list of maintained packages
  buf = ssh_cmd( socket:sock, cmd:"find /usr/portage/ -wholename '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'" );
  if( strlen( buf ) == 0 ) { # Earlier find used 'path' in place of 'wholename'
    buf = ssh_cmd( socket:sock, cmd:"find /usr/portage/ -path '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'" );
  }
  set_kb_item( name:"ssh/login/gentoo_maintained", value:buf );
  log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Gentoo" ) );

  os_register_and_report( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

  exit( 0 );
}

if( ! is_pfsense && ! is_openindiana ) {
  # EulerOS
  # nb: Sometimes there seems to be inconsistencies in the output, this was seen on a 2.0 SP0 (without SP) installation:
  # cat /etc/redhat-release: EulerOS release 2.0
  # rpm -qf /etc/redhat-release: euleros-release-2.0SP2-6.x86_64
  # cat /etc/euleros-release: EulerOS release 2.0
  #
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/euleros-release", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/euleros-release: ' + rls + '\n\n';
}

# EulerOS release 2.0
# EulerOS release 2.0 (SP2)
# EulerOS release 2.0 (SP5)
# EulerOS release 2.0 (SP9x86_64)
# EulerOS release 2.0 (SP9) -> This could be aarch64
if( rls =~ "EulerOS release" ) {

  rls = chomp( rls );
  set_kb_item( name:"ssh/login/euleros", value:TRUE );
  set_kb_item( name:"ssh/login/euleros/port", value:port );
  set_kb_item( name:"ssh/login/euleros/" + port + "/euleros_release", value:rls );
  # For Notus scanner: Reformat the release version string to be equivalent to what is listed in advisories
  # EulerOS release 2.0 (SP5)
  # EulerOS release 2.0 (SP9x86_64)
  release_match = eregmatch( pattern:"EulerOS release ([0-9]+\.[0-9]+)\s?(\((SP[0-9]+)(x86_64)?\))?", string:rls, icase:FALSE );
  if( release_match[1] ) {
    # EulerOS V2.0
    formatted_os_release = "EulerOS V" + release_match[1];
    if( release_match[3] ) {
      # EulerOS V2.0SP5
      formatted_os_release += release_match[3];
    } else {
      # EulerOS V2.0SP0
      formatted_os_release += "SP0";
    }
    if( release_match[4] ) {
      # EulerOS V2.0SP9(x86_64)
      formatted_os_release += "(" + release_match[4] + ")";
    }
    # This is a special key that will be read by the Notus scanner
    # NOTE: This is only a temporary solution until we replace all LSCs/deprecate them. Then we can use "ssh/login/release"
    set_kb_item( name:"ssh/login/release_notus", value:formatted_os_release );
  }


  # EulerOS Virtualization release 3.0.2.1 (x86_64)
  # EulerOS Virtualization for ARM 64 release 3.0.2.0 (aarch64)
  _rls = ssh_cmd( socket:sock, cmd:"cat /etc/uvp-release", return_errors:FALSE );
  if( _rls && "EulerOS Virtualization" >< _rls ) {

    set_kb_item( name:"ssh/login/euleros/is_uvp", value:TRUE );
    if( "ARM" >< _rls )
      set_kb_item( name:"ssh/login/euleros/is_uvp_arm", value:TRUE );

    set_kb_item( name:"ssh/login/euleros/" + port + "/is_uvp", value:TRUE );
    _rls = chomp( _rls );
    set_kb_item( name:"ssh/login/euleros/" + port + "/uvp_release", value:_rls );

    # For Notus scanner: Reformat the release version string to be equivalent to what is listed in advisories
    # EulerOS Virtualization release 3.0.2.1 (x86_64)
    # EulerOS Virtualization for ARM 64 release 3.0.2.0 (aarch64)
    release_match = eregmatch( pattern:"EulerOS Virtualization ([a-zA-Z0-9 ]+) ([0-9.]+)", string:_rls, icase:FALSE );
    if( release_match[1] ) {
      formatted_os_release = "EulerOS Virtualization ";
      if( "for ARM 64" >< release_match[1] ) {
        # EulerOS Virtualization for ARM 64
        formatted_os_release += "for ARM 64 ";
      }
      if( release_match[2] ) {
        # EulerOS Virtualization 3.0.2.1
        # EulerOS Virtualization for ARM 64 3.0.2.0
        formatted_os_release += release_match[2];
      }
      # This is a special key that will be read by the Notus scanner
      # NOTE: This is only a temporary solution until we replace all LSCs/deprecate them. Then we can use "ssh/login/release"
      set_kb_item( name:"ssh/login/release_notus", value:formatted_os_release );
    }

    rls = _rls + '\n(Base system: ' + rls + ")";
  }

  # uvp_version=UVP-KVM-3.0.RC2.SPC101B010
  _rls = ssh_cmd( socket:sock, cmd:"cat /etc/uvp_version", return_errors:FALSE );
  if( _rls && "uvp_version=" >< _rls ) {

    set_kb_item( name:"ssh/login/euleros/is_uvp", value:TRUE );
    if( "ARM" >< _rls )
      set_kb_item( name:"ssh/login/euleros/is_uvp_arm", value:TRUE );

    set_kb_item( name:"ssh/login/euleros/" + port + "/is_uvp", value:TRUE );
    set_kb_item( name:"ssh/login/euleros/" + port + "/uvp_version", value:chomp( _rls ) );
  }

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
    else {
      # Collect the RPMs in a different format for the Notus scanner
      buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
      if( buf ) {
        if( ! register_rpms( buf:buf, custom_key_name:"ssh/login/package_list_notus" ) )
          error = buf;
      }
    }
  }

  log_message( port:port, data:create_lsc_os_detection_report( rpm_access_error:error, detect_text:rls ) );

  exit( 0 );
}

# Non GNU/Linux platforms:

## HP-UX Operating System
if( uname =~ "hp-ux" ) {

  rls = ssh_cmd( socket:sock, cmd:"uname -r" );

  if( rls =~ "([0-9.]+)" ) {
    oskey = "HPUX";
    cpe = "cpe:/o:hp:hp-ux";
    os = "HP-UX";

    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );

    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );

    vers = eregmatch( pattern:"([0-9.]+)", string:rls );
    if( vers[1] ) {
      cpe += ":" + vers[1];
      oskey += vers[1];

      log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + vers[1] ) );
      os_register_and_report( os:os, version:vers[1], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
    } else {
      log_message( port:port, data:create_lsc_os_detection_report( detect_text:os ) );
      os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    set_kb_item( name:"ssh/login/release", value:oskey );

    exit( 0 );
  }
}

# How about FreeBSD? If the uname line begins with "FreeBSD ", we have a match.
# We need to run uname twice, because of lastlogin and motd ..
# nb: pfSense is also running on FreeBSD, see for a special handling for this at the top
uname = ssh_cmd( socket:sock, cmd:"uname -a" );

# e.g.:
# FreeBSD hostname 11.3-STABLE FreeBSD 11.3-STABLE #458 r352432M: Tue Sep 17 03:31:12 UTC 2019     root@fb11-x64-sds70.intranet:/usr/obj/usr/src/sys/SOLIDSERVER  amd64
# FreeBSD freebsd 11.3-RELEASE FreeBSD 11.3-RELEASE #0 r349754: Fri Jul  5 04:45:24 UTC 2019     root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC  amd64

if( "FreeBSD" >< uname ) {

  set_kb_item( name:"ssh/login/freebsd", value:TRUE );
  register_uname( uname:uname );
  found = 0;

  version = eregmatch( pattern:"^[^ ]+ [^ ]+ ([^ ]+)+", string:uname );
  splitup = eregmatch( pattern:"([^-]+)-([^-]+)-p([0-9]+)", string:version[1] );
  if( ! isnull( splitup ) ) {
    release    = splitup[1];
    patchlevel = splitup[3];
    found = 1;
  }

  if( found == 0 ) {
    splitup = eregmatch( pattern:"([^-]+)-RELEASE", string:version[1] );
    if( ! isnull( splitup ) ) {
      release    = splitup[1];
      patchlevel = "0";
      found = 1;
    }
  }

  if( found == 0 ) {
    splitup = eregmatch( pattern:"([^-]+)-SECURITY", string:version[1] );
    if( ! isnull( splitup ) ) {
      release = splitup[1];
      log_message( port:port, data:"We have detected you are running FreeBSD " + splitup[0] + ". It also appears that you are using freebsd-update, a binary update tool for keeping your distribution up to date. We will not be able to check your core distribution for vulnerabilities, but we will check your installed ports packages." );
      found = 2;
    }
  }

  if( found == 0 ) {
    splitup = eregmatch( pattern:"([^-]+)-(CURRENT|STABLE)", string:version[1] );
    if( ! isnull( splitup ) ) {
      release = splitup[1];
      patchlevel = "0";
      log_message( port:port, data:"We have detected you are running FreeBSD " + splitup[0] + ". It also appears that you are using a development branch of FreeBSD. Local security checks might not work as expected." );
      found = 3;
    }
  }

  if( found == 0 ) {
    osversion = ssh_cmd( socket:sock, cmd:"uname -r" );
    log_message( port:port, data:"You appear to be running FreeBSD, but we do not recognize the output format of uname: " + uname + ". Local security checks will NOT be run." );
    os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: We want to report the unknown / not detected version
    os_register_unknown_banner( banner:'Unknown FreeBSD release.\n\nuname -a: ' + uname + '\nuname -r: ' + osversion, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }

  if( found == 1 || found == 3 ) {
    set_kb_item( name:"ssh/login/freebsdrel", value:release );
    set_kb_item( name:"ssh/login/freebsdpatchlevel", value:patchlevel );
    os_register_and_report( os:"FreeBSD", version:release, patch:"p" + patchlevel, cpe:"cpe:/o:freebsd:freebsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:"FreeBSD " + release + " Patch level: " + patchlevel ) );
  } else if( found == 2 ) {
    set_kb_item( name:"ssh/login/freebsdrel", value:release );
    os_register_and_report( os:"FreeBSD", version:release, cpe:"cpe:/o:freebsd:freebsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:"FreeBSD " + release + " Patch level: Unknown" ) );
  }

  if( found != 0 ) {
    buf = ssh_cmd( socket:sock, cmd:"pkg info" );
    if( buf ) {
      if( "The package management tool is not yet installed on your system" >< buf ) {
        set_kb_item( name:"ssh/login/freebsdpkg/available", value:buf );
      } else {
        set_kb_item( name:"ssh/login/freebsdpkg", value:buf );
        set_kb_item( name:"ssh/login/freebsdpkg/available", value:TRUE );
      }
    }
  }

  exit( 0 );
}

# Whilst we're at it, lets check if it's Solaris
if( "SunOS " >< uname ) {

  set_kb_item( name:"ssh/login/solaris", value:TRUE );

  register_uname( uname:uname );

  osversion = ssh_cmd( socket:sock, cmd:"uname -r" );
  set_kb_item( name:"ssh/login/solosversion", value:osversion );

  if( match = eregmatch( pattern:"^([0-9.]+)", string:osversion ) ) {
    os_register_and_report( os:"Solaris", version:match[1], cpe:"cpe:/o:sun:solaris", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Solaris", cpe:"cpe:/o:sun:solaris", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: We want to report the unknown / not detected version
    os_register_unknown_banner( banner:'Unknown Solaris release.\n\nuname: ' + uname + '\nuname -r: ' + osversion, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }

  hardwaretype = ssh_cmd( socket:sock, cmd:"uname -p" );
  set_kb_item( name:"ssh/login/solhardwaretype", value:hardwaretype );

  if( ! is_openindiana ) {
    if( "sparc" >< hardwaretype ) {
      log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Solaris " + osversion + " Arch: SPARC" ) );
    } else {
      log_message( port:port, data:create_lsc_os_detection_report( detect_text:"Solaris " + osversion + " Arch: x86" ) );
    }
  }

  buf = ssh_cmd( socket:sock, cmd:"pkginfo" );
  set_kb_item( name:"ssh/login/solpackages", value:buf );

  buf = ssh_cmd( socket:sock, cmd:"showrev -p" );
  set_kb_item( name:"ssh/login/solpatches", value:buf );

  exit( 0 );
}

# This is just doing a basic detection, we don't have any LSCs for OpenBSD...
# OpenBSD $hostname 5.5 GENERIC#271 amd64
# OpenBSD $hostname 6.3 GENERIC#100 amd64
if( "OpenBSD " >< uname ) {

  set_kb_item( name:"ssh/login/openbsd", value:TRUE );

  register_uname( uname:uname );

  osversion = ssh_cmd( socket:sock, cmd:"uname -r" );
  set_kb_item( name:"ssh/login/openbsdversion", value:osversion );

  if( match = eregmatch( pattern:"^([0-9.]+)", string:osversion ) ) {
    os_register_and_report( os:"OpenBSD", version:match[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: We want to report the unknown / not detected version
    os_register_unknown_banner( banner:'Unknown OpenBSD release.\n\nuname: ' + uname + '\nuname -r: ' + osversion, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }
  exit( 0 );
}

#maybe it's a real OS... like Mac OS X :)
if( "Darwin" >< uname ) {

  register_uname( uname:uname );

  sw_vers_buf = ssh_cmd( socket:sock, cmd:"sw_vers" );
  log_message( port:0, data:create_lsc_os_detection_report( detect_text:'\n' + sw_vers_buf ) );

  buf = chomp( ssh_cmd( socket:sock, cmd:"sw_vers -productName" ) );
  set_kb_item( name:"ssh/login/osx_name", value:buf );

  buf = chomp( ssh_cmd( socket:sock, cmd:"sw_vers -productVersion" ) );
  if( match = eregmatch( pattern:"^([0-9.]+)", string:buf ) )
  {
    set_kb_item( name:"ssh/login/osx_version", value:match[1]);
    os_register_and_report( os:"Mac OS X / macOS", version:match[1], cpe:"cpe:/o:apple:mac_os_x", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Mac OS X / macOS", cpe:"cpe:/o:apple:mac_os_x", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: We want to report the unknown / not detected version
    os_register_unknown_banner( banner:'Unknown Mac OS X  / macOS release.\n\nsw_vers output:\n' + sw_vers_buf, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }

  buf = chomp( ssh_cmd( socket:sock, cmd:"sw_vers -buildVersion" ) );
  set_kb_item( name:"ssh/login/osx_build", value:buf );

  buf = ssh_cmd( socket:sock, cmd:"list=$(pkgutil --pkgs);for l in $list;do echo $l;v=$(pkgutil --pkg-info $l | grep version);echo ${v#version: };done;" );
  set_kb_item( name:"ssh/login/osx_pkgs", value:buf );

  exit( 0 );
}

# Minix 127.0.0.1 3.3.0 Minix 3.3.0 (GENERIC) i386
# nb: Keep down below to only catch the "uname -a" from FreeBSD above which doesn't
# contain the full PTY output / banner of Minix.
if( uname =~ "^Minix " ) {

  register_uname( uname:uname );

  set_kb_item( name:"ssh/login/minix", value:TRUE );

  # e.g.:
  # openssh-6.6.1        Open Source Secure shell client and server (remote login program)
  # openssl-1.0.1g       Secure Socket Layer and cryptographic library
  buf = chomp( ssh_cmd( socket:sock, cmd:"pkgin list" ) );
  set_kb_item( name:"ssh/login/pkgin_pkgs", value:buf );

  minix_cpe = "cpe:/o:minix3:minix";
  minix_version = eregmatch( pattern:"^Minix .* Minix ([0-9.]+) ", string:uname );
  report = "MINIX3";

  if( ! isnull( minix_version[1] ) ) {
    report += " " + minix_version[1];
    os_register_and_report( os:"MINIX3", version:minix_version[1], cpe:minix_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"MINIX3", cpe:minix_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  log_message( port:port, data:create_lsc_os_detection_report( no_lsc_support:TRUE, detect_text:report ) );
  exit( 0 );
}

if( ! is_pfsense && ! is_openindiana ) {
  # Seen on various older Linux variants or embedded systems, just as a last fallback for unknown
  # OS reporting if anything from above failed to have a little bit more info in the reporting.
  rls = ssh_cmd( socket:sock, cmd:"cat /etc/version", return_errors:FALSE );

  if( strlen( rls ) )
    _unknown_os_info += '/etc/version: ' + rls + '\n\n';
}

# TODO:
#{ "NetBSD",     "????????????????",         },
#{ "WhiteBox",   "????????????????",         },
#{ "Linspire",   "????????????????",         },
#{ "Desktop BSD","????????????????",         },
#{ "PC-BSD",     "????????????????",         },
#{ "FreeSBIE",   "????????????????",         },
#{ "JDS",        "/etc/sun-release",         },
#{ "Yellow Dog", "/etc/yellowdog-release",   },

if( uname ) {
  _unknown_os_info = 'uname: ' + uname + '\n\n' + _unknown_os_info;
  report  = 'System identifier unknown:\n\n';
  report += uname;
  report += '\n\nTherefore no local security checks applied (missing list of installed packages) ';
  report += 'though SSH login provided and works.';
} else {
  report  = 'System identifier unknown. Therefore no local security checks applied ';
  report += '(missing list of installed packages) though SSH login provided and works.';
}

if( _unknown_os_info ) {
  os_register_unknown_banner( banner:_unknown_os_info, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  report += '\n\n' + "Please see the VT 'Unknown OS and Service Banner Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108441) ";
  report += "for possible ways to identify this OS.";
}

log_message( port:port, data:report );

exit( 0 );
