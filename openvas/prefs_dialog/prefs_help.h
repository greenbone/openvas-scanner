/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */   

#ifndef _NESSUSC_PREFS_HELP_H
#define _NESSUSC_PREFS_HELP_H

#define HLP_AUTH_SERVER "Enter the server name, where the Nessusd server resides on. \
This may be a domain name or an IP address."
#ifdef DEFAULT_PORT
#define HLP_AUTH_PORT \
"Enter the port number where you will be serviced by\
 the Nessud server. With older server systems, this is\
 the port 3001, but the official port is 1241."
#else
#define HLP_AUTH_PORT \
"Enter the port number where you will be serviced by\
 the Nessud server."
#endif
#ifdef USE_ZLIB_COMPRESSION
#define HLP_CIPHER_CHOICE "Enter the channel encrytion <cipher>/<hash>:<compression>. \
A good choice for <cipher> is BLOWFISH, or TWOFISH an a good choice for <hash> is \
RIPEMD160. If your do not want any compression, use <cipher>/<hash>, only. If your \
bandwidth is a precious, use <cipher>/<hash>:9. For lowest compression (optimized \
for speed on your local computer) use <cipher>/<hash>:0."
#else
#define HLP_CIPHER_CHOICE "Enter the secure channel encrytion type as \
<cipher>/<hash>:<compression>. A good choice for <cipher> is blowfish, or twofish an \
a good choice for <hash> is ripemd160."
#endif
#define HLP_LOGIN_USER "Enter the user name where you are registerd with on the \
Nessusd server. If you log in for the first time, you will be asked for a password. \
Maybe you need to ask your Nessusd administrator to create a login for you."

#define HLP_MISC_MAX_HOSTS "Maximal of number of hosts that the server will test at \
the same time. Be aware that the remote host will spawn max_hosts x max_checks \
processes !"

#define HLP_MISC_MAX_CHECKS "Maximal number of security checks that will be launched at \
the same time against each host. Be aware that the remote host will spawn \
max_hosts x max_checks processes !"

#define HLP_TEST_FILE "Name of the remote file that several plugins will attempt \
to read"

#define HLP_SCAN_OPT_PING "If this option is checked, then nessusd will send \
some TCP packets to the remote host and will determine if the remote host \
is alive. This method does not use ICMP as ICMP is unreliable and as less \
and less hosts are answering to ICMP echo requests"

#define HLP_SCAN_OPT_REVERSE_LOOKUP "If this option is set, nessusd will do a reverse \
lookup on the IP addresses before it tests them. This may somehow slow down the \
whole test"

#define HLP_SCAN_OPT_FIREWALL "Are the remote hosts protected by a firewall ? If so \
and if we are outside the firewall, it is a good idea to turn this option ON, so that \
Nessus will perform some additional tests to check that the remote firewall is well \
configured (this option is still experimental)"

#define HLP_SCAN_OPT_OPTIMIZE "Security tests may ask the server to be \
launched if and only if some information gathered by other \
test exist in the knowledge base, or if and only if a given \
port is open. This option speeds up the test, but may \
make Nessus miss some vulnerability. If you are paranoid, \
disable this option"

#define HLP_SCAN_OPT_SAFE_CHECKS "\
Some security checks may harm the remote server, by \
disabling the remote service temporarily or until \
a reboot. If you enable this option, Nessus will \
rely on banners instead of actually performing \
a security check. You will obtain a less reliable \
report, but you will less likely disrupt the network users \
by doing a test. From a security point of view, we \
recommand you disable this option. From a sysadmin \
point of view, we recommand you enable it"


#define HLP_SCAN_OPT_USE_MAC_ADDR "\
If you enable this option, the hosts on the local network \
will be designated by their ethernet MAC address instead of \
their IP address. This is especially useful if you are using \
Nessus in a DHCP network. If unsure, disable this option"

#define HLP_SCAN_OPT_PORT_RANGE "Ports that will be scanned by Nessus. You can enter \
single ports, such as \"1-8000\"; or more complex sets, such as \"21,23,25,1024-2048,6000\". \
Put \"-1\" for no portscan, or put \"default\" to scan default ports in the Nessus services file."

#define HLP_UNSCANNED_CLOSED "To save scanning time, you may ask Nessus to declare \
TCP ports it did not scan as closed. This will result in an incomplete audit \
but it will reduce scanning time and prevent nessusd from sending packets \
to ports you did not specify. \
If this option is disabled, then Nessus will consider ports whose state it does not know as open"

#define HLP_HOST_EXPANSION_DNS "Nessus will perform an AXFR request \
(that is, a zone transfer) to the remote name server and will attempt to obtain \
the list of the hosts of the remote domain. Then, it will test each host."

#define HLP_HOST_EXPANSION_NFS "Nessus will determine which hosts \
can mount the filesystems exported by the remote server, and will test them. \
Beware : this test is recursive"

#define HLP_HOST_EXPANSION_IP "Nessus will test the whole subnet \
of the remote host. If you select this option, you should allow Nessus to \
ping the hosts before scanning them in the 'Scan options' section"


#define HLP_TARGET_PRIMARY_TARGET "The first host(s) that will be attacked by Nessus. \
The options below allow you to extend the test to a larger set of computer. You may \
define several primary targets by separating them with a comma (,). ie : \"host1,host2\""
 
#define HLP_CGI_PATH "It is possible to check for the presence of CGIs in multiple paths\
 like /cgi-bin, /cgis, /home-cgis, and so on. In that case, put all your paths here\
 separated by colons. For instance:   '/cgi-bin:/cgi-aws:/~deraison/cgi'"

#define HLP_WARNING "The warning sign means that this plugin may harm the \n\
remote host by disabling the attacked service or by crashing the host. \n\
You should be careful when you enable it since it may force you to reboot \n\
your servers or restart some services manually" 


#ifdef ENABLE_SAVE_KB

#define HLP_ENABLE_KB_SAVING "If you turn on this option, all the information \
collected about the remote hosts will be saved on the side of nessusd \
for further re-use. See http://www.nessus.org/doc/kb_saving.html for details"

#define HLP_KB_TEST_ALL "If you select this option, all the hosts selected \
in the 'Target' section of the client will be tested."

#define HLP_KB_TEST_TESTED "If you select this option, only the hosts to \
which a recent knowledge base is attached will be tested."

#define HLP_KB_TEST_UNTESTED "If you select this option, only the hosts which \
have no (or an outdated) knowledge base attached will be tested. \
Use this option to populate your knowledge bases"

#define HLP_RESTORE_KB "If you select this option, the knowledge bases \
of the remote hosts will be restored in memory if they are recent enough. \
You can use this option with the following ones to prevent nessusd \
to port scan a host which was scanned in the past, or to prevent the security \
checks that were performed in the past to be performed again."


#define HLP_KB_NO_SCANNER "If you select this option, the port scanners \
that were launched in the past against the targetted hosts will not be launched again \
and the data of the knowledge base will be used as the result of the portscan"

#define HLP_KB_NO_INFO "If you select this option, all the plugins \
that performs information gathering and which have already been \
launched against the remote hosts will not be launched again"


#define HLP_KB_NO_ATTACK "If you select this option, all the plugins \
that performs attacks and which have already been launched against the \
remote hosts will not be launched again"

#define HLP_KB_NO_DENIAL "If you select this option, all the plugins \
that may harm the remote hosts and which have already been launched \
will not be launched again"



#define HLP_KB_MAX_AGE "This value defines the maximum age (in seconds \
of a knowledge base."


#define HLP_DIFF_SCAN "If this option is set, the client will only report \
what has changed between the new scan and the last one"

#endif

#define HLP_ENABLE_DEPS_AT_RUNTIME "If you enable this option, then nessusd \
will enable the plugins that are depended on by the set of plugins you \
selected. "
#define HLP_SILENT_DEPS "If you enable this option, then nessusd \
will not report data coming from the plugins that you did not specifically \
enable. "
#endif
