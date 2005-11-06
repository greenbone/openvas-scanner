/* Nessus
 * Copyright (C) 1998 - 1999 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
 
/*
 * GENERAL CONFIGURATION FOR THE WIN32 CLIENT
 */

 
/* 
 * Socket type
 *
 * Nessus can handle two types of socket : AF_INET and AF_UNIX
 *
 * The AF_INET type allow the server and the client to be on
 * different computers, but may create security problems (until
 * someone volunteers to made the encryption)
 *
 * The AF_UNIX type is more secure, but the server and the
 * client have to be on the same computer (this is what is used
 * by default if you don't define 'USE_AF_INET'), and must
 * be launched by the same user (read : same uid)
 */
 
#define USE_AF_INET


#ifndef USE_AF_INET
/* 
 * AF_UNIX socket path (if you want to use AF_UNIX sockets)
 */
#define AF_UNIX_PATH "/var/run/nessus/nessus.sock"

#endif /* not def USE_AF_INET */


/*
 * define this if you want to see some useful debug
 * messages comming from Nessus 
 */
#undef DEBUG

/*
 * define this if you want to spot a particular
 * problem, else don't, because it throws a lot
 * of garbage to the screen
 */
#undef  DEBUGMORE


/*
 * NESSUSD SPECIFIC CONFIGURATION
 */


/*
 * Some definitions used for client/server ecryption
 * (actvated only if ENABLE_CRYPTO_LAYER is set)	
 */	

/* The default server key file and key length */
#define NESSUSD_KEYLENGTH 1024
#define NESSUSD_MAXPWDFAIL   5
#define NESSUSD_USERNAME  "nessusd"

/* The default rpc cipher nessusd will be connect to (if any) */
#define NESSUSD_RPCIPHER     "twofish/ripemd160"
#define NESSUSD_RPCAUTH_METH 3 /* auth scheme, either 1 or 3 */

/*
 * The default port on which nessusd
 * will be listenning
 */
#define DEFAULT_PORT 3001

/*
 * How much time before closing
 * the connection if nothing comes
 * from the client ? (in secs)
 */
#define CLIENT_TIMEOUT 300

/*
 * How much time before killing
 * a plugin ? (in secs)
 * (if you have a slow computer or a slow
 * network connection, set it to 320 or more)
 */
 
#define PLUGIN_TIMEOUT 160 


/*
 * Shall the server log EVERYTHING ?
 */
 
#undef LOGMORE

/*
 * Shall the server log the whole attack ?
 */
 
#undef LOG_WHOLE_ATTACK

/*
 * Host specs.
 * 
 * Set this if you are running OpenBSD < 2.1 or all FreeBSD or
 * all netBSD, or BSDi < 3.0
 *
 * If you have run this script as root, then it should be correctly
 * set up
 *
 */
#undef BSD_BYTE_ORDERING


/*
 * NESSUS CLIENT SPECIFIC CONFIGURATION
 */
 
/*
 * Build the client with GTK?
 */
#define USE_GTK

/*
 * How long before closing the 
 * connection to the server if
 * it stays mute ?
 */
#define SERVER_TIMEOUT 800
 



#define GTK_VERSION 12

#define NESS_COMPILER   "(unknown)"
#define NESS_OS_NAME    "Windows 95/98/NT"
#define NESS_OS_VERSION "(unknown)"

#define PROGNAME "Nessus"
#define NESSUS_VERSION "0.98.4"

