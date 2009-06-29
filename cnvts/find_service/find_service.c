/*
 * Find service
 *
 * This plugin is released under the GPL
 */
#define DETECT_WRAPPED_SVC
#define SMART_TCP_RW
/* #define DEBUG */

#include <includes.h>

#include <glib.h>

#define EN_NAME "Services"

#define EN_FAMILY "Service detection"

#define EN_DESC "This plugin attempts to guess which\n\
service is running on the remote ports. For instance,\n\
it searches for a web server which could listen on\n\
another port than 80 and set the results in the plugins\n\
knowledge base.\n\n\
Risk factor : None"

#define EN_COPY "Written by Renaud Deraison <deraison@cvs.nessus.org>"

#define EN_SUMM "Find what is listening on which port"


#ifdef HAVE_SSL
#define CERT_FILE "SSL certificate : "
#define KEY_FILE  "SSL private key : "
#define PEM_PASS "PEM password : "
#define CA_FILE	"CA file : "
#endif
#define CNX_TIMEOUT_PREF	"Network connection timeout : "
#define RW_TIMEOUT_PREF		"Network read/write timeout : "
#ifdef DETECT_WRAPPED_SVC
#define WRAP_TIMEOUT_PREF	"Wrapped service read timeout : "
#endif


#define NUM_CHILDREN		"Number of connections done in parallel : "


int 
plugin_init(desc)
	struct arglist *desc;
{
	plug_set_id(desc, 10330);
	plug_set_version(desc, "$Revision: 1852 $");

	plug_set_name(desc, EN_NAME);


	plug_set_category(desc, ACT_GATHER_INFO);


	plug_set_family(desc, EN_FAMILY);

	plug_set_description(desc, EN_DESC);

	plug_set_summary(desc, EN_SUMM);

	plug_set_copyright(desc, EN_COPY);
	add_plugin_preference(desc, NUM_CHILDREN, PREF_ENTRY, "6");
	add_plugin_preference(desc, CNX_TIMEOUT_PREF, PREF_ENTRY, "5");
	add_plugin_preference(desc, RW_TIMEOUT_PREF, PREF_ENTRY, "5");
#ifdef DETECT_WRAPPED_SVC
	add_plugin_preference(desc, WRAP_TIMEOUT_PREF, PREF_ENTRY, "2");
#endif

#ifdef HAVE_SSL
	add_plugin_preference(desc, CERT_FILE, PREF_FILE, "");
	add_plugin_preference(desc, KEY_FILE, PREF_FILE, "");
	add_plugin_preference(desc, PEM_PASS, PREF_PASSWORD, "");
	add_plugin_preference(desc, CA_FILE, PREF_FILE, "");

#define TEST_SSL_PREF	"Test SSL based services"
	add_plugin_preference(desc, TEST_SSL_PREF, PREF_RADIO, "Known SSL ports;All;None");
#endif
	plug_set_timeout(desc, PLUGIN_TIMEOUT * 4);
	return (0);
}




static void
register_service(desc, port, proto)
	struct arglist *desc;
	int             port;
	const char     *proto;
{
	char            k[96];

#ifdef DEBUG
	int             l;
	if (port < 0 || proto == NULL ||
	    (l = strlen(proto)) == 0 || l > sizeof(k) - 10) {
		fprintf(stderr, "find_service->register_service: invalid value - port=%d, proto=%s\n",
			port, proto == NULL ? "(null)" : proto);
		return;
	}
#endif
	/* Old "magical" key set */
	snprintf(k, sizeof(k), "Services/%s", proto);
	/* Do NOT use plug_replace_key! */
	plug_set_key(desc, k, ARG_INT, GSIZE_TO_POINTER(port));

	/*
	 * 2002-08-24 - MA - My new key set There is a problem: if
	 * register_service is called twice for a port, e.g. first with HTTP
	 * and then with SWAT, the plug_get_key function will fork. This
	 * would not happen if we registered a boolean (i.e. "known") instead
	 * of the name of the protocol. However, we *need* this name for some
	 * scripts. We'll just have to keep in mind that a fork is
	 * possible...
	 * 
	 * 2005-06-01 - MA - with plug_replace_key the problem is solved, but I
	 * wonder if this is so great...
	 */
	snprintf(k, sizeof(k), "Known/tcp/%d", port);
	plug_replace_key(desc, k, ARG_STRING, (char *) proto);
}

void 
mark_chargen_server(desc, port)
	struct arglist *desc;
	int             port;
{
	register_service(desc, port, "chargen");
	post_note(desc, port, "Chargen is running on this port");
}

void 
mark_echo_server(desc, port)
	struct arglist *desc;
	int             port;
{
	register_service(desc, port, "echo");
	post_note(desc, port, "An echo server is running on this port");
}

void 
mark_ncacn_http_server(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	char            ban[256];
	if (port == 593) {
		register_service(desc, port, "http-rpc-epmap");
		snprintf(ban, sizeof(ban), "http-rpc-epmap/banner/%d", port);
		plug_replace_key(desc, ban, ARG_STRING, buffer);
	} else {
		register_service(desc, port, "ncacn_http");
		snprintf(ban, sizeof(ban), "ncacn_http/banner/%d", port);
		plug_replace_key(desc, ban, ARG_STRING, buffer);
	}
}

void 
mark_vnc_server(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "vnc");
	snprintf(ban, sizeof(ban), "vnc/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
}

void 
mark_nntp_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "nntp");
	snprintf(ban, sizeof(ban), "nntp/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "An NNTP server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}


void 
mark_swat_server(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	register_service(desc, port, "swat");
}

void 
mark_vqserver(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	register_service(desc, port, "vqServer-admin");
}


void 
mark_mldonkey(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "mldonkey");
	snprintf(ban, sizeof(ban), "A mldonkey server is running on this port");
	post_note(desc, port, ban);
}



void 
mark_http_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "www");
	snprintf(ban, sizeof(ban), "www/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A web server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}


void 
mark_locked_adsubtract_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "AdSubtract");
	snprintf(ban, sizeof(ban), "AdSubtract/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A (locked) AdSubtract server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

static void
mark_gopher_server(struct arglist * desc, int port)
{
	register_service(desc, port, "gopher");
	post_note(desc, port, "A gopher server is running on this port");
}

#if 0
static void
mark_gnutella_servent(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[256];

	register_service(desc, port, "gnutella");
	snprintf(ban, sizeof(ban), "www/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A Gnutella servent is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}
#endif

void 
mark_rmserver(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "realserver");
	snprintf(ban, sizeof(ban), "realserver/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);

	snprintf(ban, sizeof(ban), "A RealMedia server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

void 
mark_smtp_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "smtp");
	snprintf(ban, sizeof(ban), "smtp/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);

	if (strstr(buffer, " postfix"))
		plug_replace_key(desc, "smtp/postfix", ARG_INT, (void *) 1);

	{
		char           *report = emalloc(255 + strlen(buffer));
		char           *t = strchr(buffer, '\n');
		if (t)
			t[0] = 0;
		snprintf(report, 255 + strlen(buffer), "An SMTP server is running on this port%s\n\
Here is its banner : \n%s",
			 get_encaps_through(trp), buffer);
		post_note(desc, port, report);
		efree(&report);
	}
}

void
mark_snpp_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512], *report, *t;
	register_service(desc, port, "snpp");
	snprintf(ban, sizeof(ban), "snpp/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);

	report = emalloc(255 + strlen(buffer));
	t = strchr(buffer, '\n');
	if (t != NULL)
		*t = '\0';
	snprintf(report, 255 + strlen(buffer),
		 "An SNPP server is running on this port%s\n\
Here is its banner : \n%s",
		 get_encaps_through(trp), buffer);
	post_note(desc, port, report);
	efree(&report);
}

void 
mark_ftp_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	register_service(desc, port, "ftp");

	if (buffer != NULL) {
		char            ban[255];

		snprintf(ban, sizeof(ban), "ftp/banner/%d", port);
		plug_replace_key(desc, ban, ARG_STRING, buffer);
	}
	if (buffer != NULL) {
		char           *report = emalloc(255 + strlen(buffer));
		char           *t = strchr(buffer, '\n');
		if (t != NULL)
			t[0] = '\0';
		snprintf(report, 255 + strlen(buffer), "An FTP server is running on this port%s.\n\
Here is its banner : \n%s",
			 get_encaps_through(trp), buffer);
		post_note(desc, port, report);
		efree(&report);
	} else {
		char            report[255];
		snprintf(report, sizeof(report), "An FTP server is running on this port%s.",
			 get_encaps_through(trp));
		post_note(desc, port, report);
	}
}

void
mark_ssh_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port;
	char           *buffer;
	int             trp;
{
	register_service(desc, port, "ssh");
	while ((buffer[strlen(buffer) - 1] == '\n') ||
	       (buffer[strlen(buffer) - 1] == '\r'))
		buffer[strlen(buffer) - 1] = '\0';
	post_note(desc, port, "An ssh server is running on this port");
}

void
mark_http_proxy(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	/* the banner is in www/banner/port */
	register_service(desc, port, "http_proxy");
	snprintf(ban, sizeof(ban), "An HTTP proxy is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

void
mark_pop_server(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	char           *c = strchr(buffer, '\n');
	char            ban[512];
	char           *buffer2;
	int             i;
	if (c)
		c[0] = 0;
	buffer2 = estrdup(buffer);
	for (i = 0; i < strlen(buffer2); i++)
		buffer2[i] = tolower(buffer2[i]);
	if (!strcmp(buffer2, "+ok")) {
		register_service(desc, port, "pop1");
		snprintf(ban, sizeof(ban), "pop1/banner/%d", port);
		plug_replace_key(desc, ban, ARG_STRING, buffer);
	} else if (strstr(buffer2, "pop2")) {
		register_service(desc, port, "pop2");
		snprintf(ban, sizeof(ban), "pop2/banner/%d", port);
		plug_replace_key(desc, ban, ARG_STRING, buffer);
		post_note(desc, port, "a pop2 server is running on this port");
	} else {
		register_service(desc, port, "pop3");
		snprintf(ban, sizeof(ban), "pop3/banner/%d", port);
		plug_replace_key(desc, ban, ARG_STRING, buffer);
		post_note(desc, port, "A pop3 server is running on this port");
	}
	efree(&buffer2);
}

void
mark_imap_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "imap");
	snprintf(ban, sizeof(ban), "imap/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	{
		snprintf(ban, sizeof(ban), "An IMAP server is running on this port%s",
			 get_encaps_through(trp));
		post_note(desc, port, ban);
	}
}

void
mark_auth_server(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	register_service(desc, port, "auth");
	post_note(desc, port, "An identd server is running on this port");
}


/*
 * Postgres, MySQL & CVS pserver detection by Vincent Renardias
 * <vincent@strongholdnet.com>
 */
void
mark_postgresql(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	register_service(desc, port, "postgresql");
	/* if (port != 5432) */
	post_note(desc, port, "A PostgreSQL server is running on this port");
}

void
mark_mysql(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	register_service(desc, port, "mysql");
	/* if (port != 3306) */
	post_note(desc, port, "A MySQL server is running on this port");
}

void
mark_cvspserver(desc, port, buffer, trp)
	struct arglist *desc;
	int             port;
	char           *buffer;
	int             trp;
{
	register_service(desc, port, "cvspserver");
	/* if (port != 2401) */
	post_info(desc, port, "A CVS pserver server is running on this port");
}


void
mark_cvsupserver(desc, port, buffer, trp)
	struct arglist *desc;
	int             port;
	char           *buffer;
	int             trp;
{
	register_service(desc, port, "cvsup");
	post_info(desc, port, "A CVSup server is running on this port");
}


void
mark_cvslockserver(desc, port, buffer, trp)
	struct arglist *desc;
	int             port;
	char           *buffer;
	int             trp;
{
	register_service(desc, port, "cvslockserver");
	/* if (port != 2401) */
	post_info(desc, port, "A CVSLock server server is running on this port");
}

void
mark_rsyncd(desc, port, buffer, trp)
	struct arglist *desc;
	int             port;
	char           *buffer;
	int             trp;
{
	register_service(desc, port, "rsyncd");
	post_info(desc, port, "An rsync server is running on this port");
}


void
mark_wild_shell(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{

	register_service(desc, port, "wild_shell");

	post_hole(desc, port, "A shell seems to be running on this port ! (this is a possible backdoor)");
}

void
mark_telnet_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "telnet");
	{
		snprintf(ban, sizeof(ban), "A telnet server seems to be running on this port%s",
			 get_encaps_through(trp));
		post_note(desc, port, ban);
	}
}

void
mark_gnome14_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "gnome14");
	{
		snprintf(ban, sizeof(ban), "A Gnome 1.4 server seems to be running on this port%s",
			 get_encaps_through(trp));
		post_note(desc, port, ban);
	}
}

void
mark_eggdrop_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "eggdrop");
	{
		snprintf(ban, sizeof(ban), "An eggdrop IRC bot seems to be running a control server on this port%s",
			 get_encaps_through(trp));
		post_note(desc, port, ban);
	}
}

void
mark_netbus_server(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{

	register_service(desc, port, "netbus");
	post_hole(desc, port, "NetBus is running on this port");
}


void
mark_linuxconf(desc, port, buffer)
	struct arglist *desc;
	int             port;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "linuxconf");
	snprintf(ban, sizeof(ban), "linuxconf/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	post_note(desc, port, "Linuxconf is running on this port");
}

static void
mark_finger_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[256];


	register_service(desc, port, "finger");

	snprintf(tmp, sizeof(tmp), "A finger server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}


static void
mark_vtun_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[255];

	snprintf(tmp, sizeof(tmp), "vtun/banner/%d", port);
	plug_replace_key(desc, tmp, ARG_STRING, (char *) banner);

	register_service(desc, port, "vtun");

	if (banner == NULL) {
		snprintf(tmp, sizeof(tmp), "A VTUN server seems to be running on this port%s",
			 get_encaps_through(trp));
	} else
		snprintf(tmp, sizeof(tmp), "A VTUN server seems to be running on this port%s\nHere is its banner:\n%s\n",
			 get_encaps_through(trp), banner);



	post_note(desc, port, tmp);
}

static void
mark_uucp_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[255];

	snprintf(tmp, sizeof(tmp), "uucp/banner/%d", port);
	plug_replace_key(desc, tmp, ARG_STRING, (char *) banner);

	register_service(desc, port, "uucp");

	snprintf(tmp, sizeof(tmp), "An UUCP server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}



static void
mark_lpd_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[255];

	register_service(desc, port, "lpd");
	snprintf(tmp, sizeof(tmp), "A LPD server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}


/* http://www.lysator.liu.se/lyskom/lyskom-server/ */
static void
mark_lyskom_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[255];

	register_service(desc, port, "lyskom");
	snprintf(tmp, sizeof(tmp), "A LysKOM server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}

/* http://www.emailman.com/ph/ */
static void
mark_ph_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[255];

	register_service(desc, port, "ph");
	snprintf(tmp, sizeof(tmp), "A PH server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}

static void
mark_time_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[256];

	register_service(desc, port, "time");
	snprintf(tmp, sizeof(tmp), "A time server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}


static void
mark_ens_server(desc, port, banner, trp)
	struct arglist *desc;
	char           *banner;
	int             port, trp;
{
	char            tmp[255];
	register_service(desc, port, "iPlanetENS");

	snprintf(tmp, sizeof(tmp), "An iPlanet ENS (Event Notification Server) seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}

static void
mark_citrix_server(desc, port, banner, trp)
	struct arglist *desc;
	const char     *banner;
	int             port, trp;
{
	char            tmp[255];

	register_service(desc, port, "citrix");
	snprintf(tmp, sizeof(tmp), "a Citrix server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, tmp);
}

static void
mark_giop_server(desc, port, banner, trp)
	struct arglist *desc;
	const char     *banner;
	int             port, trp;
{
	char            tmp[255];

	register_service(desc, port, "giop");
	snprintf(tmp, sizeof(tmp), "A GIOP-enabled service is running on this port%s",
		 get_encaps_through(trp));

	post_note(desc, port, tmp);
}

static void
mark_exchg_routing_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];

	register_service(desc, port, "exchg-routing");
	snprintf(ban, sizeof(ban), "exchg-routing/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	{
		snprintf(ban, sizeof(ban), "A Microsoft Exchange routing server is running on this port%s",
			 get_encaps_through(trp));
		post_note(desc, port, ban);
	}
}


static void
mark_tcpmux_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            msg[255];

	register_service(desc, port, "tcpmux");
	snprintf(msg, sizeof(msg), "A tcpmux server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, msg);
}


static void
mark_BitTorrent_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	unsigned char  *buffer;
{
	char            msg[255];

	register_service(desc, port, "BitTorrent");
	snprintf(msg, sizeof(msg), "A BitTorrent server seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, msg);
}

static void
mark_smux_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	unsigned char  *buffer;
{
	char            msg[255];

	register_service(desc, port, "smux");
	snprintf(msg, sizeof(msg), "A SNMP Multiplexer (smux) seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, msg);
}


/*
 * LISa is the LAN Information Server that comes
 * with KDE in Mandrake Linux 9.0. Apparently
 * it usually runs on port 7741.
 */
static void
mark_LISa_server(desc, port, banner, trp)
	struct arglist *desc;
	unsigned char  *banner;
	int             port, trp;
{
	char            tmp[255];

	register_service(desc, port, "LISa");
	snprintf(tmp, sizeof(tmp), "A LISa daemon is running on this port%s",
		 get_encaps_through(trp));

	post_note(desc, port, tmp);
}


/*
 * msdtc is Microsoft Distributed Transaction Coordinator
 *
 * Thanks to jtant@shardwebdesigns.com for reporting it
 *
 */
static void
mark_msdtc_server(desc, port, buffer)
	struct arglist *desc;
	int             port;
	unsigned char  *buffer;
{
	register_service(desc, port, "msdtc");
	post_note(desc, port, "A MSDTC server is running on this port");
}

static void
mark_pop3pw_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "pop3pw");
	snprintf(ban, sizeof(ban), "pop3pw/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A pop3pw server is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, ban);
}

/*
 * whois++ server, thanks to Adam Stephens - http://roads.sourceforge.net/index.php
 *
 * 00: 25 20 32 32 30 20 4c 55 54 20 57 48 4f 49 53 2b    % 220 LUT WHOIS+
 * 10: 2b 20 73 65 72 76 65 72 20 76 32 2e 31 20 72 65    + server v2.1 re
 * 20: 61 64 79 2e 20 20 48 69 21 0d 0a 25 20 32 30 30    ady.  Hi!..% 200
 * 30: 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 47     Searching for G
 * 40: 45 54 26 2f 26 48 54 54 50 2f 31 2e 30 0d 0a 25    ET&/&HTTP/1.0..%
 * 50: 20 35 30 30 20 45 72 72 6f 72 20 70 61 72 73 69     500 Error parsi
 * 60: 6e 67 20 42 6f 6f 6c 65 61 6e 20 65 78 70 72 65    ng Boolean expre
 * 70: 73 73 69 6f 6e 0d 0a                               ssion..
 */

static void
mark_whois_plus2_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "whois++");
	snprintf(ban, sizeof(ban), "whois++/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A whois++ server is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, ban);
}

/*
 * mon server, thanks to Rafe Oxley <rafe.oxley@moving-edge.net>
 * (http://www.kernel.org/software/mon/)
 * 
 * An unknown server is running on this port. If you know what it is, please
 * send this banner to the Nessus team: 00: 35 32 30 20 63 6f 6d 6d 61 6e 64
 * 20 63 6f 75 6c 520 command coul 10: 64 20 6e 6f 74 20 62 65 20 65 78 65 63
 * 75 74 65 d not be execute 20: 64 0a d.
 */
static void
mark_mon_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "mon");
	snprintf(ban, sizeof(ban), "mon/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A mon server is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, ban);
}


static void
mark_fw1(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "cpfw1");
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A CheckPoint FW1 SecureRemote or FW1 FWModule server is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, ban);
}

/*
 * From: Mike Gitarev [mailto:mik@bofh.lv]
 *
 * http://www.psychoid.lam3rz.de
 * 00: 3a 57 65 6c 63 6f 6d 65 21 70 73 79 42 4e 43 40    :Welcome!psyBNC@
 * 10: 6c 61 6d 33 72 7a 2e 64 65 20 4e 4f 54 49 43 45    lam3rz.de NOTICE
 * 20: 20 2a 20 3a 70 73 79 42 4e 43 32 2e 33 2e 31 2d     * :psyBNC2.3.1-
 * 30: 37 0d 0a                                           7..
 */

static void
mark_psybnc(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "psybnc");
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A PsyBNC IRC proxy is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, ban);
}

/*
 * From "Russ Paton" <russell.paton@blueyonder.co.uk>
 *
 * 00: 49 43 59 20 32 30 30 20 4f 4b 0d 0a 69 63 79 2d ICY 200 OK..icy-
 * 10: 6e 6f 74 69 63 65 31 3a 3c 42 52 3e 54 68 69 73 notice1:<BR>This
 * 20: 20 73 74 72 65 61 6d 20 72 65 71 75 69 72 65 73 stream requires
 */
static void
mark_shoutcast_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "shoutcast");
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A shoutcast server is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, ban);
}


/*
 * From "Hendrickson, Chris" <chendric@qssmeds.com>
 * 00: 41 64 73 47 6f 6e 65 20 42 6c 6f 63 6b 65 64 20    AdsGone Blocked
 * 10: 48 54 4d 4c 20 41 64                               HTML Ad
 */

static void
mark_adsgone(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "adsgone");
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "An AdsGone (a popup banner blocking server) is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, ban);
}



/*
 * Sig from  harm vos <h.vos@fwn.rug.nl> :
 * 
 * 00: 2a 20 41 43 41 50 20 28 49 4d 50 4c 45 4d 45 4e    * ACAP (IMPLEMEN 10:
 * 54 41 54 49 4f 4e 20 22 43 6f 6d 6d 75 6e 69 47    TATION "CommuniG 20: 61
 * 74 65 20 50 72 6f 20 41 43 41 50 20 34 2e 30    ate Pro ACAP 4.0 30: 62 39
 * 22 29 20 28 53 54 41 52 54 54 4c 53 29 20    b9") (STARTTLS) 40: 28 53 41
 * 53 4c 20 22 4c 4f 47 49 4e 22 20 22 50    (SASL "LOGIN" "P 50: 4c 41 49 4e
 * 22 20 22 43 52 41 4d 2d 4d 44 35 22    LAIN" "CRAM-MD5" 60: 20 22 44 49 47
 * 45 53 54 2d 4d 44 35 22 20 22 4e     "DIGEST-MD5" "N 70: 54 4c 4d 22 29 20
 * 28 43 4f 4e 54 45 58 54 4c 49    TLM") (CONTEXTLI 80: 4d 49 54 20 22 32 30
 * 30 22 29 0d 0a                MIT "200")..
 * 
 * The ACAP protocol allows a client (mailer) application to connect to the
 * Server computer and upload and download the application preferences,
 * configuration settings and other datasets (such as personal address
 * books).
 */
static void
mark_acap_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "acap");
	snprintf(ban, sizeof(ban), "acap/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	{
		snprintf(ban, sizeof(ban), "An ACAP server is running on this port%s",
			 get_encaps_through(trp));
		post_note(desc, port, ban);
	}
}


/*
 * Sig from Cedric Foll <cedric.foll@ac-rouen.fr>
 * 
 * 
 * 00: 53 6f 72 72 79 2c 20 79 6f 75 20 28 31 37 32 2e Sorry, you (172. 10: 33
 * 30 2e 31 39 32 2e 31 30 33 29 20 61 72 65 20 30.192.103)are 20: 6e 6f 74
 * 20 61 6d 6f 6e 67 20 74 68 65 20 61 6c not among the al 30: 6c 6f 77 65 64
 * 20 68 6f 73 74 73 2e 2e 2e 0a lowed hosts....
 * 
 * The ACAP protocol allows a client (mailer) application to connect to the
 * Server computer and upload and download the application preferences,
 * configuration settings and other datasets (such as personal address
 * books).
 */
static void
mark_nagiosd_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "nagiosd");
	snprintf(ban, sizeof(ban), "A nagiosd server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);

}

/*
 * Sig from  Michael Löffler <nimrod@n1mrod.de>
 * 
 * 00: 5b 54 53 5d 0a 65 72 72 6f 72 0a                   [TS].error.
 * 
 * That's Teamspeak2 rc2 Server - http://www.teamspeak.org/
 */
static void
mark_teamspeak2_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "teamspeak2");
	snprintf(ban, sizeof(ban), "A teamspeak2 server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);

}


/*
 * Sig from <Gary.Crowell@experian.com>
 * 
 * 
 * 
 * 
 * 00: 4c 61 6e 67 75 61 67 65 20 72 65 63 65 69 76 65    Language receive 10:
 * 64 20 66 72 6f 6d 20 63 6c 69 65 6e 74 3a 20 47    d from client: G 20: 45
 * 54 20 2f 20 48 54 54 50 2f 31 2e 30 0d 0a 53    ET / HTTP/1.0..S 30: 65 74
 * 6c 6f 63 61 6c 65 3a 20 0a                   etlocale: .
 * 
 * Port 9090 is for WEBSM, the GUI SMIT tool that AIX RMC  (port 657) is
 * configured and used with.  (AIX Version 5.1)
 */
static void
mark_websm_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "websm");
	snprintf(ban, sizeof(ban), "A WEBSM server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);

}

/*
 * From Gary Crowell :
 * 00: 43 4e 46 47 41 50 49                               CNFGAPI
 */
static void
mark_ofa_express_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "ofa_express");
	snprintf(ban, sizeof(ban), "An OFA/Express server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);

}



/*
 * From Pierre Abbat <phma@webjockey.net> 00: 53 75 53 45 20 4d 65 74 61 20
 * 70 70 70 64 20 28 SuSE Meta pppd ( 10: 73 6d 70 70 70 64 29 2c 20 56 65 72
 * 73 69 6f 6e    smpppd), Version 20: 20 30 2e 37 38 0d 0a
 * 0.78..
 */
static void
mark_smppd_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "smppd");
	snprintf(ban, sizeof(ban), "A SuSE Meta pppd server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

/*
 * From DaLiV <daliv@apollo.lv
 *
 * 00: 45 52 52 20 55 4e 4b 4e 4f 57 4e 2d 43 4f 4d 4d ERR UNKNOWN-COMM
 * 10: 41 4e 44 0a 45 52 52 20 55 4e 4b 4e 4f 57 4e 2d AND.ERR UNKNOWN-
 * 20: 43 4f 4d 4d 41 4e 44 0a COMMAND.
 */
static void
mark_upsmon_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "upsmon");
	snprintf(ban, sizeof(ban), "An upsd/upsmon server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

/*
 * From Andrew Yates <pilot1_ace@hotmail.com>
 *
 * 00: 63 6f 6e 6e 65 63 74 65 64 2e 20 31 39 3a 35 31    connected. 19:51
 * 10: 20 2d 20 4d 61 79 20 32 35 2c 20 32 30 30 33 2c     - May 25, 2003,
 * 20: 20 53 75 6e 64 61 79 2c 20 76 65 72 3a 20 4c 65     Sunday, ver: Le
 * 30: 67 65 6e 64 73 20 32 2e 31                         gends 2.1
 */
static void
mark_sub7_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "sub7");
	snprintf(ban, sizeof(ban), "The Sub7 trojan is running on this port%s",
		 get_encaps_through(trp));
	post_hole(desc, port, ban);
}


/*
 * From "Alex Lewis" <alex@sgl.org.au>
 *
 *  00: 53 50 41 4d 44 2f 31 2e 30 20 37 36 20 42 61 64    SPAMD/1.0 76 Bad
 *  10: 20 68 65 61 64 65 72 20 6c 69 6e 65 3a 20 47 45     header line: GE
 *  20: 54 20 2f 20 48 54 54 50 2f 31 2e 30 0d 0d 0a       T /
 */
static void
mark_spamd_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "spamd");
	snprintf(ban, sizeof(ban), "a spamd server (part of spamassassin) is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

/* Thanks to Mike Blomgren */
static void
mark_quicktime_streaming_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "quicktime-streaming-server");
	snprintf(ban, sizeof(ban), "a quicktime streaming server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

/* Thanks to Allan <als@bpal.com> */
static void
mark_dameware_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "dameware");
	snprintf(ban, sizeof(ban), "a dameware server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

static void
mark_stonegate_auth_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "SG_ClientAuth");
	snprintf(ban, sizeof(ban), "a StoneGate authentication server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}



void
mark_listserv_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "listserv");
	{
		snprintf(ban, sizeof(ban), "A LISTSERV daemon seems to be running on this port%s",
			 get_encaps_through(trp));
		post_note(desc, port, ban);
	}
}


void
mark_fssniffer(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "FsSniffer");
	{
		snprintf(ban, sizeof(ban), "A FsSniffer backdoor seems to be running on this port%s",
			 get_encaps_through(trp));
		post_hole(desc, port, ban);
	}
}

void
mark_remote_nc_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "RemoteNC");
	{
		snprintf(ban, sizeof(ban), "A RemoteNC backdoor seems to be running on this port%s",
			 get_encaps_through(trp));
		post_hole(desc, port, ban);
	}
}



/* Do not use register_service for unknown and wrapped services! */

#ifdef DETECT_WRAPPED_SVC
static void
mark_wrapped_svc(desc, port, delta)
	struct arglist *desc;
	int             port, delta;
{
	char            msg[256];

	snprintf(msg, sizeof(msg), "The service closed the connection after %d seconds without sending any data\n\
It might be protected by some TCP wrapper\n", delta);
	post_note(desc, port, msg);
	/* Do NOT use plug_replace_key! */
	plug_set_key(desc, "Services/wrapped", ARG_INT, GSIZE_TO_POINTER(port));
}
#endif

static const char *
port_to_name(int port)
{
	/* Note: only includes services that are recognized by this plugin! */
	switch (port) {
		case 7:return "Echo";
	case 19:
		return "Chargen";
	case 21:
		return "FTP";
	case 22:
		return "SSH";
	case 23:
		return "Telnet";
	case 25:
		return "SMTP";
	case 37:
		return "Time";
	case 70:
		return "Gopher";
	case 79:
		return "Finger";
	case 80:
		return "HTTP";
	case 98:
		return "Linuxconf";
	case 109:
		return "POP2";
	case 110:
		return "POP3";
	case 113:
		return "AUTH";
	case 119:
		return "NNTP";
	case 143:
		return "IMAP";
	case 220:
		return "IMAP3";
	case 443:
		return "HTTPS";
	case 465:
		return "SMTPS";
	case 563:
		return "NNTPS";
	case 593:
		return "Http-Rpc-Epmap";
	case 873:
		return "Rsyncd";
	case 901:
		return "SWAT";
	case 993:
		return "IMAPS";
	case 995:
		return "POP3S";
#if 0
	case 1080:
		return "SOCKS";
#endif
	case 1109:
		return "KPOP";	/* ? */
	case 2309:
		return "Compaq Management Server";
	case 2401:
		return "CVSpserver";
	case 3128:
		return "Squid";
	case 3306:
		return "MySQL";
	case 5000:
		return "VTUN";
	case 5432:
		return "Postgres";
	case 8080:
		return "HTTP-Alt";
	}
	return NULL;
}

#if 0
static void
mark_unknown_svc(desc, port, banner, trp)
	struct arglist *desc;
	int             port, trp;
	const unsigned char *banner;
{
	char            tmp[1600], *norm = NULL;

	/* Do NOT use plug_replace_key! */
	plug_set_key(desc, "Services/unknown", ARG_INT, (void *) port);
	snprintf(tmp, sizeof(tmp), "unknown/banner/%d", port);
	plug_replace_key(desc, tmp, ARG_STRING, (char *) banner);

	norm = (char *) port_to_name(port);
	*tmp = '\0';
	if (norm != NULL) {
		snprintf(tmp, sizeof(tmp), "An unknown service is running on this port%s.\n\
It is usually reserved for %s",
			 get_encaps_through(trp), norm);
	}
	if (*tmp != '\0')
		post_note(desc, port, tmp);
}
#endif

static void
mark_gnuserv(desc, port)
	struct arglist *desc;
	int             port;
{
	register_service(desc, port, "gnuserv");
	post_note(desc, port, "gnuserv is running on this port");
}

static void
mark_iss_realsecure(desc, port)
	struct arglist *desc;
	int             port;
{
	register_service(desc, port, "issrealsecure");
	post_note(desc, port, "ISS RealSecure is running on this port");
}

static void
mark_vmware_auth(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];


	register_service(desc, port, "vmware_auth");

	snprintf(ban, sizeof(ban), "A VMWare authentication daemon is running on this port%s:\n%s",
		 get_encaps_through(trp), buffer);
	post_note(desc, port, ban);

}

static void
mark_interscan_viruswall(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "interscan_viruswall");

	snprintf(ban, sizeof(ban), "An interscan viruswall is running on this port%s:\n%s",
		 get_encaps_through(trp), buffer);
	post_note(desc, port, ban);
}

static void
mark_ppp_daemon(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "pppd");

	snprintf(ban, sizeof(ban), "A PPP daemon is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

static void
mark_zebra_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "zebra");
	snprintf(ban, sizeof(ban), "zebra/banner/%d", port);
	plug_replace_key(desc, ban, ARG_STRING, buffer);
	snprintf(ban, sizeof(ban), "A zebra daemon (bgpd or zebrad) is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

static void
mark_ircxpro_admin_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "ircxpro_admin");

	snprintf(ban, sizeof(ban), "An IRCXPro administrative server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}


static void
mark_gnocatan_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "gnocatan");

	snprintf(ban, sizeof(ban), "A gnocatan game server is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

/* Thanks to Owell Crow */
static void
mark_pbmaster_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "power-broker-master");

	snprintf(ban, sizeof(ban), "A PowerBroker master server is running on this port%s:\n%s",
		 get_encaps_through(trp), buffer);
	post_note(desc, port, ban);
}

/* Thanks to Paulo Jorge */
static void
mark_dictd_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "dicts");

	snprintf(ban, sizeof(ban), "A dictd server is running on this port%s:\n%s",
		 get_encaps_through(trp), buffer);
	post_note(desc, port, ban);
}


/* Thanks to Tony van Lingen */
static void
mark_pnsclient(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "pNSClient");

	snprintf(ban, sizeof(ban), "A Netsaint plugin (pNSClient.exe) is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

/* Thanks to Jesus D. Munoz */
static void
mark_veritas_backup(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];
	register_service(desc, port, "VeritasNetBackup");

	snprintf(ban, sizeof(ban), "VeritasNetBackup is running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}

static void
mark_pblocald_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "power-broker-master");

	snprintf(ban, sizeof(ban), "A PowerBroker locald server is running on this port%s:\n%s",
		 get_encaps_through(trp), buffer);
	post_note(desc, port, ban);
}

void
mark_jabber_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[255];
	register_service(desc, port, "jabber");
	snprintf(ban, sizeof(ban), "jabber daemon seems to be running on this port%s",
		 get_encaps_through(trp));
	post_note(desc, port, ban);
}



static void
mark_avotus_mm_server(desc, port, buffer, trp)
	struct arglist *desc;
	int             port, trp;
	char           *buffer;
{
	char            ban[512];

	register_service(desc, port, "avotus_mm");

	snprintf(ban, sizeof(ban), "An avotus 'mm' server is running on this port%s:\n%s",
		 get_encaps_through(trp), buffer);
	post_note(desc, port, ban);
}

static void
mark_socks_proxy(desc, port, ver)
	struct arglist *desc;
	int             port, ver;
{
	char            str[256];

	snprintf(str, sizeof(str), "socks%d", ver);
	register_service(desc, port, str);
	snprintf(str, sizeof(str), "A SOCKS%d proxy is running on this port. ", ver);
	post_note(desc, port, str);
}

static void
mark_direct_connect_hub(desc, port, trp)
	struct arglist *desc;
	int             port, trp;
{
	char            str[256];

	register_service(desc, port, "DirectConnectHub");
	snprintf(str, sizeof(str), "A Direct Connect Hub is running on this port%s", get_encaps_through(trp));
	post_note(desc, port, str);
}

/*
 * We determine if the 4 bytes we received look like a date. We
 * accept clocks desynched up to 3 years;
 *
 * MA 2002-09-09 : time protocol (RFC 738) returns number of seconds since
 * 1900-01-01, while time() returns nb of sec since 1970-01-01.
 * The difference is 2208988800 seconds.
 * By the way, although the RFC is imprecise, it seems that the returned
 * integer is in "network byte order" (i.e. big endian)
 */
#define MAX_SHIFT	(3*365*86400)
#define DIFF_1970_1900	2208988800U

static int
may_be_time(time_t * rtime)
{
#ifndef ABS
#define ABS(x) (((x) < 0) ? -(x):(x))
#endif
	time_t          now = time(NULL);
	int             rt70 = ntohl(*rtime) - DIFF_1970_1900;

	if (ABS(now - rt70) < MAX_SHIFT)
		return 1;
	else
		return 0;
}

/*
 * References:
 * IANA assigned number
 *
 * http://www.tivoli.com/support/public/Prodman/public_manuals/td/ITAME/GC32-0848-00/en_US/HTML/amwebmst09.htm
 * http://java.sun.com/webservices/docs/1.0/tutorial/doc/WebAppSecurity6.html
 */

static int
known_ssl_port(int port)
{
	switch (port) {
		case 261:	/* Nsiiops = IIOP name service over tls/ssl */
		case 443:	/* HTTPS */
		case 448:	/* ddm-ssl */
		case 465:	/* SMTPS */
		case 563:	/* NNTPS */
		case 585:	/* imap4-ssl (not recommended) */
		case 614:	/* SSLshell */
		case 636:	/* LDAPS */
		case 684:	/* Corba IIOP SSL */
		case 902:	/* VMWare auth daemon */
		case 989:	/* FTPS data */
		case 990:	/* FTPS control */
		case 992:	/* telnets */
		case 993:	/* IMAPS */
		case 994:	/* IRCS */
		case 995:	/* POP3S */
		case 1241:	/* Nessus */
		case 2381:	/* Compaq Web Management (HTTPS) */
		case 2478:	/* SecurSight Authentication Server (SSL) */
		case 2479:	/* SecurSight Event Logging Server (SSL) */
		case 2482:	/* Oracle GIOP SSL */
		case 2484:	/* Oracle TTC SSL */
		case 2679:	/* Sync Server SSL */
		case 3077:	/* Orbix 2000 Locator SSL */
		case 3078:	/* Orbix 2000 Locator SSL */
		case 3269:	/* Microsoft Global Catalog w/ LDAP/SSL */
		case 3471:	/* jt400 SSL */
		case 5007:	/* WSM Server SSL */
		case 7135:	/* IBM Tivoli Access Manager runtime
				 * environment - SSL Server Port */
		case 8443:	/* Tomcat */
		case 9443:	/* Websphere internal secure server */
		case 10000:	/* WebMin+SSL */
		case 19201:	/* SilkPerformer agent (secure connection) */
		return 1;
	default:
		return 0;
	}
	/* NOTREACHED */
}

#ifndef MSG_DONTWAIT
/* From http://www.kegel.com/dkftpbench/nonblocking.html */
static int
setNonblocking(int fd)
{
	int             flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/*
	 * Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX
	 * 3.2.5.
	 */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIONBIO, &flags);
#endif
}
#endif


static int 
plugin_do_run(desc, h, test_ssl)
	struct arglist *desc;
	struct arglist *h;
	int             test_ssl;
{
	char           *head = "Ports/tcp/";
	u_short         unknown[65535];
	int             num_unknown = 0;
	int             len_head = strlen(head);

	int             rw_timeout = 5, cnx_timeout = 5, wrap_timeout = 3;
	int             x, timeout;
	char           *rw_timeout_s = get_plugin_preference(desc, RW_TIMEOUT_PREF);
	char           *cnx_timeout_s = get_plugin_preference(desc, CNX_TIMEOUT_PREF);
#ifdef DETECT_WRAPPED_SVC
	char           *wrap_timeout_s = get_plugin_preference(desc, WRAP_TIMEOUT_PREF);
#endif
	unsigned char  *p;
	fd_set          rfds, wfds, xfds;
	struct timeval  tv;
	char            k[32];
#ifdef DEBUG
	struct arglist *hostinfos = arg_get_value(desc, "HOSTNAME");
	struct in_addr *p_ip = arg_get_value(hostinfos, "IP");
#endif

	if (rw_timeout_s != NULL && (x = atoi(rw_timeout_s)) > 0)
		rw_timeout = x;
	if (cnx_timeout_s != NULL && (x = atoi(cnx_timeout_s)) > 0)
		cnx_timeout = x;
#ifdef DETECT_WRAPPED_SVC
	if (wrap_timeout_s != NULL && (x = atoi(wrap_timeout_s)) >= 0)
		wrap_timeout = x;
#endif

	bzero(unknown, sizeof(unknown));

	while (h && h->next) {
		if ((strlen(h->name) > len_head) && !strncmp(h->name, head, len_head)) {
			int             cnx;
			char           *line;
			char           *origline;
			int             trp, i;
			char            buffer[2049];
			unsigned char  *banner = NULL, *bannerHex = NULL;
			int             banner_len;
			int             port = atoi(h->name + len_head);
			int             flg = 0;
			int             unindentified_service = 0;
			int             three_digits = 0;
			int             maybe_wrapped = 0;
			char            kb[64];
			int             get_sent = 0;
			int             ssl_port = known_ssl_port(port);
			int             std_port = ssl_port || (port_to_name(port) != NULL);
			int             cnx_timeout2 = std_port ? cnx_timeout * 2 : cnx_timeout;
			int             rw_timeout2 = std_port ? rw_timeout * 2 : rw_timeout;
			struct timeval  tv1, tv2;
			int             diff_tv = 0, diff_tv2 = 0;
			int             type, no_banner_grabbed = 0;

#define DIFFTV1000(t1,t2)	((t1.tv_sec - t2.tv_sec)*1000 + (t1.tv_usec - t2.tv_usec)/1000)

			bzero(buffer, sizeof(buffer));
			banner_len = 0;
			snprintf(kb, sizeof(kb), "BannerHex/%d", port);
			bannerHex = plug_get_key(desc, kb, &type);
			if (type == ARG_STRING && bannerHex != NULL && bannerHex[0] != '\0') {
				int             i, c1, c2;
				banner_len = strlen((char *) bannerHex) / 2;
				if (banner_len >= sizeof(buffer))
					banner_len = sizeof(buffer) - 1;
				for (i = 0; i < banner_len; i++) {
					c1 = bannerHex[2 * i];
					if (c1 >= 0 && c1 <= 9)
						c1 -= '0';
					else if (c1 >= 'a' && c1 <= 'f')
						c1 -= 'a';
					else if (c1 >= 'A' && c1 <= 'F')
						c1 -= 'A';
					else
						banner_len = 0;	/* Invalid value */
					c2 = bannerHex[2 * i + 1];
					if (c2 >= 0 && c2 <= 9)
						c2 -= '0';
					else if (c2 >= 'a' && c2 <= 'f')
						c2 -= 'a';
					else if (c2 >= 'A' && c2 <= 'F')
						c2 -= 'A';
					else
						banner_len = 0;	/* Invalid value */
					buffer[i] = c1 << 4 | c2;
				}
				buffer[i] = '\0';
				if (banner_len > 0)
					banner = (unsigned char *) buffer;
#ifdef DEBUG
				fprintf(stderr, "find_service(%s): found hex banner in KB for port %d. len=%d\n", inet_ntoa(*p_ip), port, banner_len);
#endif
			}
			if (banner_len == 0) {
				snprintf(kb, sizeof(kb), "Banner/%d", port);
				banner = plug_get_key(desc, kb, &type);
				if (type == ARG_STRING && banner != NULL) {
					banner_len = strlen((char *) banner);
#ifdef DEBUG
					fprintf(stderr, "find_service(%s): found banner in KB for port %d. len=%d\n", inet_ntoa(*p_ip), port, banner_len);
#endif
				}
			}
			if (banner_len > 0) {
#ifdef DEBUG
				fprintf(stderr, "find_service(%s): banner is known on port %d - will not open a new connection\n", inet_ntoa(*p_ip), port);
#endif
				cnx = -1;
				trp = NESSUS_ENCAPS_IP;
			} else {
#ifdef DEBUG
				fprintf(stderr, "find_service(%s): banner is unknown on port %d - connecting...\n", inet_ntoa(*p_ip), port);
#endif
				if (banner != NULL)
					efree(&banner);
				banner = NULL;
				if (test_ssl == 2 || (test_ssl == 1 && ssl_port)) {
					cnx = open_stream_connection_unknown_encaps5(desc, port, cnx_timeout2, &trp, &diff_tv);
					diff_tv /= 1000;	/* Now in milliseconds */
				} else {
					(void) gettimeofday(&tv1, NULL);
					trp = NESSUS_ENCAPS_IP;
					cnx = open_stream_connection(desc, port, trp, cnx_timeout2);
					(void) gettimeofday(&tv2, NULL);
					diff_tv = DIFFTV1000(tv2, tv1);
				}
			}

			if (cnx >= 0 || banner_len > 0) {
				int             len, line_len;
				int             realfd = -1;

				if (cnx >= 0) {
					realfd = nessus_get_socket_from_connection(cnx);
					snprintf(k, sizeof(k), "FindService/CnxTime1000/%d", port);
					plug_replace_key(desc, k, ARG_INT, GSIZE_TO_POINTER(diff_tv));
					snprintf(k, sizeof(k), "FindService/CnxTime/%d", port);
					plug_replace_key(desc, k, ARG_INT, GSIZE_TO_POINTER(((diff_tv + 500) / 1000)));
					if (diff_tv / 1000 > cnx_timeout)
						plug_replace_key(desc, "/tmp/SlowFindService", ARG_INT, GSIZE_TO_POINTER(1));
				}
#ifdef DEBUG
				fprintf(stderr, "find_service(%s): Port %d is open. \"Transport\" is %d\n", inet_ntoa(*p_ip), port, trp);
#endif
				plug_set_port_transport(desc, port, trp);
				(void) stream_set_timeout(port, rw_timeout2);

#ifdef HAVE_SSL
				if (IS_ENCAPS_SSL(trp)) {
					char            report[160];
					snprintf(report, sizeof(report), "A %s server answered on this port\n",
						 get_encaps_name(trp));
					post_note(desc, port, report);
					plug_set_key(desc, "Transport/SSL", ARG_INT, (void *) port);
				}
#endif


#define HTTP_GET	"GET / HTTP/1.0\r\n\r\n"

				len = 0;
				timeout = 0;
				if (banner_len > 0) {
					len = banner_len;
					if (banner != (unsigned char *) buffer) {
						if (len >= sizeof(buffer))
							len = sizeof(buffer) - 1;
						memcpy(buffer, banner, len);
						buffer[len] = '\0';
					}
				} else {
					snprintf(kb, sizeof(kb), "/tmp/NoBanner/%d", port);
					p = plug_get_key(desc, kb, &type);
					if (p != NULL) {
						if (type == ARG_INT)
							no_banner_grabbed = GPOINTER_TO_SIZE(p);
						else if (type == ARG_STRING)
							no_banner_grabbed = atoi((char *) p);
					}
#ifdef DEBUG
					fprintf(stderr, "find_service(%s): no banner on port %d according to KB\n", inet_ntoa(*p_ip), port);
#endif

					if (!no_banner_grabbed) {
#ifdef SMART_TCP_RW
						if (trp == NESSUS_ENCAPS_IP && realfd >= 0) {
					select_again:
							FD_ZERO(&rfds);
							FD_ZERO(&wfds);
							FD_SET(realfd, &rfds);
							FD_SET(realfd, &wfds);

							(void) gettimeofday(&tv1, NULL);
							tv.tv_usec = 0;
							tv.tv_sec = rw_timeout2;
							x = select(realfd + 1, &rfds, &wfds, NULL, &tv);
							if (x < 0) {
								if (errno == EINTR)
									goto select_again;
								perror("select");
							} else if (x == 0)
								timeout = 1;
							else if (x > 0) {
								if (FD_ISSET(realfd, &rfds)) {
									len = read_stream_connection_min(cnx, buffer, 1, sizeof(buffer) - 2);
								}
							}
							(void) gettimeofday(&tv2, NULL);
							diff_tv = DIFFTV1000(tv2, tv1);
						}
					} else {	/* No banner was found
							 * by openvas_tcp_scanner */
#ifdef DEBUG
						fprintf(stderr, "find_service(%s): no banner was found by openvas_tcp_scanner on port %d - sending GET without waiting\n", inet_ntoa(*p_ip), port);
#endif
						len = 0;
						timeout = 0;
					}

					if (len <= 0 && !timeout)
#endif
					{
#ifdef DEBUG
						if (!no_banner_grabbed)
							fprintf(stderr, "No banner on port %d - sending GET\n", port);
#endif
						write_stream_connection(cnx, HTTP_GET, sizeof(HTTP_GET) - 1);
						(void) gettimeofday(&tv1, NULL);
						get_sent = 1;
						buffer[sizeof(buffer) - 1] = '\0';
						len = read_stream_connection(cnx, buffer, sizeof(buffer) - 1);
#if 1
						/*
						 * Try to work around broken
						 * web server (or "magic
						 * read" bug??)
						 */
						if (len > 0 && len < 8 && strncmp(buffer, "HTTP/1.", len) == 0) {
							int             len2 = read_stream_connection(cnx, buffer + len, sizeof(buffer) - 1 - len);
							if (len2 > 0)
								len += len2;
						}
#endif
						(void) gettimeofday(&tv2, NULL);
						diff_tv = DIFFTV1000(tv2, tv1);
					}
					if (len > 0) {
						snprintf(k, sizeof(k), "FindService/RwTime1000/%d", port);
						plug_replace_key(desc, k, ARG_INT, GSIZE_TO_POINTER(diff_tv));
						snprintf(k, sizeof(k), "FindService/RwTime/%d", port);
						plug_replace_key(desc, k, ARG_INT, GSIZE_TO_POINTER((diff_tv + 500) / 1000));
						if (diff_tv / 1000 > rw_timeout)
							plug_replace_key(desc, "/tmp/SlowFindService", ARG_INT, GSIZE_TO_POINTER(1));
					}
				}

				if (len > 0) {
					banner = emalloc(len + 1);
					memcpy(banner, buffer, len);
					banner[len] = '\0';

					for (i = 0; i < len; i++)
						buffer[i] = tolower(buffer[i]);

					line = estrdup(buffer);

					if (strchr(line, '\n') != NULL) {
						char           *t = strchr(line, '\n');
						t[0] = '\0';
					}
					if (isdigit(banner[0]) && isdigit(banner[1]) && isdigit(banner[2]) &&
					    (banner[3] == '\0' || isspace(banner[3]) || banner[3] == '-')) {
						/*
						 * Do NOT use
						 * plug_replace_key!
						 */
						plug_set_key(desc, "Services/three_digits", ARG_INT, GSIZE_TO_POINTER(port));
						/*
						 * Do *not* set
						 * Known/tcp/<port> to
						 * "three_digits": the
						 * service must remain
						 * "unknown"
						 */
						three_digits = 1;
					}
					if (get_sent)
						snprintf(kb, sizeof(kb), "FindService/tcp/%d/get_http", port);
					else
						snprintf(kb, sizeof(kb), "FindService/tcp/%d/spontaneous", port);
					plug_replace_key(desc, kb, ARG_STRING, banner);

					{
						char            buf2[sizeof(buffer) * 2 + 1];
						int             y, flag = 0;

						strcat(kb, "Hex");

						if (len >= sizeof(buffer))
							len = sizeof(buffer);

						for (y = 0; y < len; y++) {
							snprintf(buf2 + 2 * y, sizeof(buf2) - (2 * y), "%02x", (unsigned char) banner[y]);
							if (banner[y] == '\0')
								flag = 1;
						}
						buf2[2 * y] = '\0';
						if (flag)
							plug_replace_key(desc, kb, ARG_STRING, buf2);
					}

					origline = estrdup((char *) banner);
					if (strchr(origline, '\n') != NULL) {
						char           *t = strchr(origline, '\n');
						t[0] = '\0';
					}
					line_len = strlen(origline);

					/*
				         * Many services run on the top of an HTTP protocol,
				         * so the HTTP test is not an 'ELSE ... IF'
				         */
					if ((!strncmp(line, "http/1.", 7) ||
					     strstr((char *) banner, "<title>Not supported</title>"))) {	/* <- broken hp
														 * jetdirect */
						flg++;
						if (!(port == 5000 && (strstr(line, "http/1.1 400 bad request") != NULL)) &&
						    !(strncmp(line, "http/1.0 403 forbidden", strlen("http/1.0 403 forbidden")) == 0 && strstr(buffer, "server: adsubtract") != NULL))
							mark_http_server(desc, port, banner, trp);

					}
					/*
				         * RFC 854 defines commands between 240 and 254
				         * shouldn't we look for them too?
				         */
					if (((u_char) buffer[0] == 255) && (((u_char) buffer[1] == 251) || ((u_char) buffer[1] == 252) || ((u_char) buffer[1] == 253) || ((u_char) buffer[1] == 254)))
						mark_telnet_server(desc, port, origline, trp);
					else if (((u_char) buffer[0] == 0) && ((u_char) buffer[1] == 1) && ((u_char) buffer[2] == 1) && ((u_char) buffer[3] == 0))
						mark_gnome14_server(desc, port, origline, trp);
					else if (strncmp(line, "http/1.0 403 forbidden", strlen("http/1.0 403 forbidden")) == 0 && strstr(buffer, "server: adsubtract") != NULL) {
						mark_locked_adsubtract_server(desc, port, banner, trp);
					} else if (strstr((char *) banner, "Eggdrop") != NULL &&
						   strstr((char *) banner, "Eggheads") != NULL)
						mark_eggdrop_server(desc, port, origline, trp);
					else if (strncmp(line, "$lock ", strlen("$lock ")) == 0)
						mark_direct_connect_hub(desc, port, trp);
					else if (len > 34 && strstr(&(buffer[34]), "iss ecnra"))
						mark_iss_realsecure(desc, port, origline, trp);
					else if (len == 4 && origline[0] == 'Q' && origline[1] == 0 && origline[2] == 0 && origline[3] == 0)
						mark_fw1(desc, port, origline, trp);
					else if (strstr(line, "adsgone blocked html ad") != NULL)
						mark_adsgone(desc, port, origline, trp);
					else if (strncmp(line, "icy 200 ok", strlen("icy 200 ok")) == 0)
						mark_shoutcast_server(desc, port, origline, trp);
					else if (
						 (!strncmp(line, "200", 3) && (strstr(line, "running eudora internet mail server"))) ||
						 (strstr(line, "+ok applepasswordserver") != NULL)
						)
						mark_pop3pw_server(desc, port, origline, trp);
					else if ((strstr(line, "smtp") || strstr(line, "simple mail transfer") || strstr(line, "mail server") || strstr(line, "messaging") || strstr(line, "Weasel")) && !strncmp(line, "220", 3))
						mark_smtp_server(desc, port, origline, trp);
					else if (strstr(line, "220 ***************") || strstr(line, "220 eSafe@"))	/* CISCO SMTP (?) - see
															 * bug #175 */
						mark_smtp_server(desc, port, origline, trp);
					else if (strstr(line, "220 esafealert") != NULL)
						mark_smtp_server(desc, port, origline, trp);
					else if (strncmp(line, "220", 3) == 0 &&
						 strstr(line, "groupwise internet agent") != NULL)
						mark_smtp_server(desc, port, origline, trp);
					else if (strncmp(line, "220", 3) == 0 && strstr(line, " SNPP ") != NULL)
						mark_snpp_server(desc, port, origline, trp);
					else if (strncmp(line, "200", 3) == 0 &&
					      strstr(line, "mail ") != NULL)
						mark_smtp_server(desc, port, origline, trp);
					else if (strncmp(line, "421", 3) == 0 && strstr(line, "smtp ") != NULL)
						mark_smtp_server(desc, port, origline, trp);
					else if (line[0] != '\0' && (strncmp(line + 1, "host '", 6) == 0) && strstr(line, "mysql") != NULL)
						mark_mysql(desc, port, origline, trp);
					else if (!strncmp(line, "efatal", 6) || !strncmp(line, "einvalid packet length", strlen("einvalid packet length")))
						mark_postgresql(desc, port, origline, trp);
					else if (strstr(line, "cvsup server ready") != NULL)
						mark_cvsupserver(desc, port, origline, trp);
					else if (!strncmp(line, "cvs [pserver aborted]:", 22) ||
						 !strncmp(line, "cvs [server aborted]:", 21))
						mark_cvspserver(desc, port, origline, trp);
					else if (!strncmp(line, "cvslock ", 8))
						mark_cvslockserver(desc, port, origline, trp);
					else if (!strncmp(line, "@rsyncd", 7))
						mark_rsyncd(desc, port, origline, trp);
					else if ((len == 4) && may_be_time((time_t *) banner))
						mark_time_server(desc, port, banner, trp);
					else if (strstr(buffer, "rmserver") || strstr(buffer, "realserver"))
						mark_rmserver(desc, port, origline, trp);
					else if ((strstr(line, "ftp") || strstr(line, "winsock") || strstr(line, "axis network camera") || strstr(line, "netpresenz") || strstr(line, "serv-u") || strstr(line, "service ready for new user")) && !strncmp(line, "220", 3))
						mark_ftp_server(desc, port, origline, trp);
					else if (strncmp(line, "220-", 4) == 0)	/* FTP server with a
										 * long banner */
						mark_ftp_server(desc, port, NULL, trp);
					else if (strstr(line, "220") && strstr(line, "whois+"))
						mark_whois_plus2_server(desc, port, origline, trp);
					else if (strstr(line, "520 command could not be executed"))
						mark_mon_server(desc, port, origline, trp);
					else if (strstr(line, "ssh-"))
						mark_ssh_server(desc, port, origline);
					else if (!strncmp(line, "+ok", 3) || (!strncmp(line, "+", 1) && strstr(line, "pop")))
						mark_pop_server(desc, port, origline);
					else if (strstr(line, "imap4") && !strncmp(line, "* ok", 4))
						mark_imap_server(desc, port, origline, trp);
					else if (strstr(line, "*ok iplanet messaging multiplexor"))
						mark_imap_server(desc, port, origline, trp);
					else if (strstr(line, "*ok communigate pro imap server"))
						mark_imap_server(desc, port, origline, trp);
					else if (strstr(line, "* ok courier-imap"))
						mark_imap_server(desc, port, origline, trp);
					else if (strncmp(line, "giop", 4) == 0)
						mark_giop_server(desc, port, origline, trp);
					else if (strstr(line, "microsoft routing server"))
						mark_exchg_routing_server(desc, port, origline, trp);
					/* Apparently an iPlanet ENS server */
					else if (strstr(line, "gap service ready"))
						mark_ens_server(desc, port, origline, trp);
					else if (strstr(line, "-service not available"))
						mark_tcpmux_server(desc, port, origline, trp);
					/*
					 * Citrix sends 7f 7f 49 43 41, that
					 * we converted to lowercase
					 */
					else if (strlen(line) > 2 && line[0] == 0x7F && line[1] == 0x7F && strncmp(&line[2], "ica", 3) == 0)
						mark_citrix_server(desc, port, origline, trp);

					else if (strstr(origline, " INN ") || strstr(origline, " Leafnode ") ||
						 strstr(line, "  nntp daemon") ||
						 strstr(line, " nnrp service ready") ||
						 strstr(line, "posting ok") || strstr(line, "posting allowed") ||
						 strstr(line, "502 no permission") ||
						 (strcmp(line, "502") == 0 && strstr(line, "diablo") != NULL))
						mark_nntp_server(desc, port, origline, trp);
					else if (strstr(buffer, "networking/linuxconf") || strstr(buffer, "networking/misc/linuxconf") || strstr(buffer, "server: linuxconf"))
						mark_linuxconf(desc, port, banner);
					else if (strncmp(buffer, "gnudoit:", 8) == 0)
						mark_gnuserv(desc, port);
					else if ((buffer[0] == '0' && strstr(buffer, "error.host\t1") != NULL) ||
						 (buffer[0] == '3' && strstr(buffer, "That item is not currently available")))
						mark_gopher_server(desc, port);
					else if (strstr(buffer, "www-authenticate: basic realm=\"swat\""))
						mark_swat_server(desc, port, banner);
					else if (strstr(buffer, "vqserver") &&
						 strstr(buffer, "www-authenticate: basic realm=/"))
						mark_vqserver(desc, port, banner);
					else if (strstr(buffer, "1invalid request") != NULL)
						mark_mldonkey(desc, port, banner);
					else if (strstr(buffer, "get: command not found"))
						mark_wild_shell(desc, port, origline);
					else if (strstr(buffer, "microsoft windows") != NULL &&
						 strstr(buffer, "c:\\") != NULL &&
						 strstr(buffer, "(c) copyright 1985-") != NULL &&
						 strstr(buffer, "microsoft corp.") != NULL)
						mark_wild_shell(desc, port, origline);
					else if (strstr(buffer, "netbus"))
						mark_netbus_server(desc, port, origline);
					else if (strstr(line, "0 , 0 : error : unknown-error") ||
						 strstr(line, "0, 0: error: unknown-error") ||
						 strstr(line, "get : error : unknown-error") ||
						 strstr(line, "0 , 0 : error : invalid-port"))
						mark_auth_server(desc, port, origline);
					else if (!strncmp(line, "http/1.", 7) && strstr(line, "proxy"))	/* my proxy "HTTP/1.1
													 * 502 Proxy Error" */
						mark_http_proxy(desc, port, banner, trp);
					else if (!strncmp(line, "http/1.", 7) && strstr(buffer, "via: "))
						mark_http_proxy(desc, port, banner, trp);
					else if (!strncmp(line, "http/1.", 7) && strstr(buffer, "proxy-connection: "))
						mark_http_proxy(desc, port, banner, trp);
					else if (!strncmp(line, "http/1.", 7) && strstr(buffer, "cache") &&
						 strstr(line, "bad request"))
						mark_http_proxy(desc, port, banner, trp);
#if 0
					else if (strncmp(line, "http/1.", 7) == 0 &&
					 strstr(buffer, "gnutella") != NULL)
						mark_gnutella_servent(desc, port, banner, trp);
#endif
					else if (!strncmp(origline, "RFB 00", 6) && strstr(line, ".00"))
						mark_vnc_server(desc, port, origline);
					else if (!strncmp(line, "ncacn_http/1.", 13))
						mark_ncacn_http_server(desc, port, origline);
					else if (line_len >= 14 &&	/* no ending \r\n */
						 line_len <= 18 &&	/* full GET request
									 * length */
						 strncmp(origline, HTTP_GET, line_len) == 0)
						mark_echo_server(desc, port, origline);
					else if (strstr((char *) banner, "!\"#$%&'()*+,-./") && strstr((char *) banner, "ABCDEFGHIJ") && strstr((char *) banner, "abcdefghij") && strstr((char *) banner, "0123456789"))
						mark_chargen_server(desc, port, banner);
					else if (strstr(line, "vtun server"))
						mark_vtun_server(desc, port, banner, trp);
					else if (strcmp(line, "login: password: ") == 0)
						mark_uucp_server(desc, port, banner, trp);
					else if (strcmp(line, "bad request") == 0 ||	/* See bug # 387 */
						 strstr(line, "invalid protocol request (71): gget / http/1.0") ||
						 (strncmp(line, "lpd:", 4) == 0) ||
						 (strstr(line, "lpsched") != NULL) ||
						 (strstr(line, "malformed from address") != NULL) ||
						 (strstr(line, "no connect permissions") != NULL) ||	/* <- RH 8 lpd */
					   strcmp(line, "bad request") == 0)
						mark_lpd_server(desc, port, banner, trp);
					else if (strstr(line, "%%lyskom unsupported protocol"))
						mark_lyskom_server(desc, port, banner, trp);
					else if (strstr(line, "598:get:command not recognized"))
						mark_ph_server(desc, port, banner, trp);
					else if (strstr(line, "BitTorrent prot"))
						mark_BitTorrent_server(desc, port, banner, trp);
					else if (banner[0] == 'A' && banner[1] == 0x01 && banner[2] == 0x02 && banner[3] == '\0')
						mark_smux_server(desc, port, banner, trp);
					else if (!strncmp(line, "0 succeeded\n", strlen("0 succeeded\n")))
						mark_LISa_server(desc, port, banner, trp);
					else if (strlen((char *) banner) == 3 && banner[2] == '\n')
						mark_msdtc_server(desc, port, banner, trp);
					else if ((!strncmp(line, "220", 3) && strstr(line, "poppassd")))
						mark_pop3pw_server(desc, port, origline, trp);
					else if (strstr(line, "welcome!psybnc@") != NULL)
						mark_psybnc(desc, port, origline, trp);
					else if (strncmp(line, "* acap ", strlen("* acap ")) == 0)
						mark_acap_server(desc, port, origline, trp);
					else if (strstr(origline, "Sorry, you (") != NULL &&
						 strstr(origline, "are not among the allowed hosts...\n") != NULL)
						mark_nagiosd_server(desc, port, origline, trp);
					else if (strstr(line, "[ts].error") != NULL ||
					    strstr(line, "[ts].\n") != NULL)
						mark_teamspeak2_server(desc, port, origline, trp);
					else if (strstr(origline, "Language received from client:") &&
					     strstr(origline, "Setlocale:"))
						mark_websm_server(desc, port, origline, trp);
					else if (strncmp(origline, "CNFGAPI", 7) == 0)
						mark_ofa_express_server(desc, port, origline, trp);
					else if (strstr(line, "suse meta pppd") != NULL)
						mark_smppd_server(desc, port, origline, trp);
					else if (strncmp(origline, "ERR UNKNOWN-COMMAND", strlen("ERR UNKNOWN-COMMAND")) == 0)
						mark_upsmon_server(desc, port, origline, trp);
					else if (strncmp(line, "connected. ", strlen("connected. ")) == 0 &&
					    strstr(line, "legends") != NULL)
						mark_sub7_server(desc, port, origline, trp);
					else if (strncmp(line, "spamd/", strlen("spamd/")) == 0)
						mark_spamd_server(desc, port, origline, trp);
					else if (strstr(line, " dictd ") && strncmp(line, "220", 3) == 0)
						mark_dictd_server(desc, port, origline, trp);
					else if (strncmp(line, "220 ", 4) == 0 &&
						 strstr(line, "vmware authentication daemon") != NULL)
						mark_vmware_auth(desc, port, origline, trp);
					else if (strncmp(line, "220 ", 4) == 0 &&
						 strstr(line, "interscan version") != NULL)
						mark_interscan_viruswall(desc, port, origline, trp);
					else if ((strlen((char *)banner) > 1) && (banner[0] == '~') && (banner[strlen((char *) banner) - 1] == '~') &&
					(strchr((char *) banner, '}') != NULL))
						mark_ppp_daemon(desc, port, origline, trp);
					else if (strstr((char *) banner, "Hello, this is zebra ") != NULL)
						mark_zebra_server(desc, port, origline, trp);
					else if (strstr(line, "ircxpro ") != NULL)
						mark_ircxpro_admin_server(desc, port, origline, trp);
					else if (strncmp(origline, "version report", strlen("version report")) == 0)
						mark_gnocatan_server(desc, port, origline, trp);
					else if (strncmp(origline, "RTSP/1.0", strlen("RTSP/1.0")) &&
					  strstr(origline, "QTSS/") != NULL)
						mark_quicktime_streaming_server(desc, port, origline, trp);
					else if (strlen(origline) >=2 && origline[0] == 0x30 && origline[1] == 0x11 && origline[2] == 0)
						mark_dameware_server(desc, port, origline, trp);
					else if (strstr(line, "stonegate firewall") != NULL)
						mark_stonegate_auth_server(desc, port, origline, trp);
					else if (strncmp(line, "pbmasterd", strlen("pbmasterd")) == 0)
						mark_pbmaster_server(desc, port, origline, trp);
					else if (strncmp(line, "pblocald", strlen("pblocald")) == 0)
						mark_pblocald_server(desc, port, origline, trp);
					else if (strncmp(line, "<stream:error>invalid xml</stream:error>",
							 strlen("<stream:error>invalid xml</stream:error>")) == 0)
						mark_jabber_server(desc, port, origline, trp);
					else if (strncmp(line, "/c -2 get ctgetoptions", strlen("/c -2 get ctgetoptions")) == 0)
						mark_avotus_mm_server(desc, port, origline, trp);
					else if (strncmp(line, "error:wrong password", strlen("error:wrong password")) == 0)
						mark_pnsclient(desc, port, origline, trp);
					else if (strncmp(line, "1000      2", strlen("1000      2")) == 0)
						mark_veritas_backup(desc, port, origline, trp);
					else if (strstr(line, "the file name you specified is invalid") &&
						 strstr(line, "listserv"))
						mark_listserv_server(desc, port, origline, trp);
					else if (strncmp(line, "control password:", strlen("control password:")) == 0)
						mark_fssniffer(desc, port, origline, trp);
					else if (strncmp(line, "remotenc control password:", strlen("remotenc control password:")) == 0)
						mark_remote_nc_server(desc, port, origline, trp);
					else if (((p = (unsigned char *) strstr((char *) banner, "finger: GET: no such user")) != NULL &&
						  strstr((char *) banner, "finger: /: no such user") != NULL &&
						  strstr((char *) banner, "finger: HTTP/1.0: no such user") != NULL) ||
						 strstr((char *) banner, "Login       Name               TTY         Idle    When    Where") ||
						 strstr((char *) banner, "Line     User") ||
						 strstr((char *) banner, "Login name: GET")) {
						char            c = '\0';
						if (p != NULL) {
							while (p - banner > 0 && isspace(*p))
								p--;
							c = *p;
							*p = '\0';
						}
						mark_finger_server(desc, port, p ? banner : NULL, trp);

						if (p != NULL)
							*p = c;
					} else if (banner[0] == 5 && banner[1] <= 8 &&
					   banner[2] == 0 && banner[3] <= 4)
						mark_socks_proxy(desc, port, 5);
					else if (banner[0] == 0 && banner[1] >= 90 && banner[1] <= 93)
						mark_socks_proxy(desc, port, 4);
					else
						unindentified_service = !flg;
					efree(&line);
					efree(&origline);
				}
				 /* len >= 0 */ 
				else {
#ifdef DEBUG
					fprintf(stderr, "find_service(%s): could not read anything from port %d\n", inet_ntoa(*p_ip), port);
#endif
					unindentified_service = 1;
#define TESTSTRING	"OpenVAS Wrap Test"
					if (trp == NESSUS_ENCAPS_IP && wrap_timeout > 0)
#if 0
						if (write_stream_connection(cnx, TESTSTRING, sizeof(TESTSTRING) - 1) <= 0)
#endif
							maybe_wrapped = 1;
				}
				if (cnx > 0)
					close_stream_connection(cnx);

#ifdef DETECT_WRAPPED_SVC
				/*
			         * I'll clean this later. Meanwhile, we will not print a silly message
			         * for rsh and rlogin.
			         */
				if (port == 513 /* rlogin */ || port == 514 /* rsh */ )
					maybe_wrapped = 0;

				if (maybe_wrapped	/* && trp ==
							 * NESSUS_ENCAPS_IP &&
				        wrap_timeout > 0 */ ) {
					int             nfd, fd, x, flag = 0;
					char            b;

#ifdef DEBUG
					fprintf(stderr, "find_service(%s): potentially wrapped service on port %d\n", inet_ntoa(*p_ip), port);
#endif
					nfd = open_stream_connection(desc, port, NESSUS_ENCAPS_IP, cnx_timeout2);
					if (nfd >= 0) {
						fd = nessus_get_socket_from_connection(nfd);
#if 0
						fprintf(stderr, "open_stream_connection(port=%d) succeeded\n", port);
#endif
				select_again2:
						FD_ZERO(&rfds);
						FD_ZERO(&xfds);
						FD_SET(fd, &rfds);
						FD_SET(fd, &xfds);
						tv.tv_sec = wrap_timeout;
						tv.tv_usec = 0;

#ifndef MSG_DONTWAIT
						setNonblocking(fd);
#endif
						signal(SIGALRM, SIG_IGN);

						(void) gettimeofday(&tv1, NULL);
						x = select(fd + 1, &rfds, NULL, &xfds, &tv);
						(void) gettimeofday(&tv2, NULL);
						diff_tv2 = DIFFTV1000(tv2, tv1);
#ifdef DEBUG
						fprintf(stderr, "find_service(%s): select(port=%d)=%d after %d.%03d s on %d\n", inet_ntoa(*p_ip), port, x, diff_tv2, diff_tv2 / 1000, wrap_timeout);
#endif
						if (x < 0) {
							if (errno == EINTR)
								goto select_again2;
							perror("select");
						} else if (x > 0) {
							errno = 0;
#ifdef MSG_DONTWAIT
							x = recv(fd, &b, 1, MSG_DONTWAIT);
#else
							x = recv(fd, &b, 1, 0);
#endif


							if (x == 0 || (x < 0 && errno == EPIPE)) {
								/*
							         * If the service quickly closes the connection when we
							         * send garbage but not when we don't send anything, it
							         * is not wrapped
							         */
								flag = 1;
							}
						} else {
							/*
							 * Timeout - one last
							 * check
							 */
							errno = 0;
#ifdef MSG_DONTWAIT
							if (send(fd, "Z", 1, MSG_DONTWAIT) < 0)
#else
							if (send(fd, "Z", 1, 0) < 0)
#endif
							{
								perror("send");
								if (errno == EPIPE)
									flag = 1;
							}
						}
						close_stream_connection(nfd);
						if (flag) {
							if (diff_tv2 <= 2 * diff_tv + 1) {
								mark_wrapped_svc(desc, port, diff_tv2 / 1000);
								unindentified_service = 0;
							}
#if defined DEBUG
							else
								fprintf(stderr, "\
The service on port %s:%d closes the connection in %d.%03d s when we send garbage,\n\
and in %d.%03d when we just wait. It is  probably not wrapped\n",
									inet_ntoa(*p_ip), port,
									diff_tv / 1000, diff_tv % 1000,
									diff_tv2 / 1000, diff_tv2 % 1000);
#endif
						}
					}
				}
#endif

				if (unindentified_service && port != 139)
					/*
					 * port 139 can't be marked as
					 * 'unknown'
					 */
				{
					unknown[num_unknown++] = port;
#if 0
					/*
					 * find_service_3digits will run
					 * after us
					 */
					if (!three_digits)
						mark_unknown_svc(desc, port, banner, trp);
#endif
				}
				efree(&banner);
			}
#ifdef DEBUG
			else
				fprintf(stderr, "find_service(%s): could not connect to port %d\n", inet_ntoa(*p_ip), port);
#endif

		}
		if (h)
			h = h->next;
	}

	return (0);
}



#define MAX_SONS 128

static pid_t    sons[MAX_SONS];

static void 
sigterm(int s)
{
	int             i;
	for (i = 0; i < MAX_SONS; i++) {
		if (sons[i] != 0)
			kill(sons[i], SIGTERM);
	}
	_exit(0);
}

static void 
sigchld(int s)
{
	int             i;
	for (i = 0; i < MAX_SONS; i++) {
		waitpid(sons[i], NULL, WNOHANG);
	}
}

static int 
fwd_data(int in, int out, pid_t sender)
{
	int             e;
	static char    *buf = NULL;
	static int      bufsz = 0;
	int             type;



	e = internal_recv(in, &buf, &bufsz, &type);
	if (e <= 0)
		return -1;
	e = internal_send(out, buf, type);

	if (bufsz > 65535) {
		efree(&buf);
		buf = NULL;
		bufsz = 0;
	}
	return 0;
}

int 
plugin_run(desc)
	struct arglist *desc;
{
	struct arglist *h = plug_get_oldstyle_kb(desc);

	struct arglist *ag;
	struct arglist *sons_args[MAX_SONS];
	int             sons_pipe[MAX_SONS][2];
	int             num_ports = 0;
	char           *num_sons_s = get_plugin_preference(desc, NUM_CHILDREN);
	int             num_sons = 10;
	int             port_per_son;
	int             i;
	char           *head = "Ports/tcp/";
	struct arglist *globals = arg_get_value(desc, "globals");
	int             one_true_pipe = GPOINTER_TO_SIZE(arg_get_value(globals, "global_socket"));
	int             test_ssl = 0;
#ifdef HAVE_SSL
	char           *key = get_plugin_preference(desc, KEY_FILE);
	char           *cert = get_plugin_preference(desc, CERT_FILE);
	char           *pempass = get_plugin_preference(desc, PEM_PASS);
	char           *cafile = get_plugin_preference(desc, CA_FILE);
	char           *test_ssl_s = get_plugin_preference(desc, TEST_SSL_PREF);



	if (key && key[0] != '\0')
		key = (char *) get_plugin_preference_fname(desc, key);
	else
		key = NULL;

	if (cert && cert[0] != '\0')
		cert = (char *) get_plugin_preference_fname(desc, cert);
	else
		cert = NULL;

	if (cafile && cafile[0] != '\0')
		cafile = (char *) get_plugin_preference_fname(desc, cafile);
	else
		cafile = NULL;

	test_ssl = 1;
	if (test_ssl_s != NULL) {
		if (strcmp(test_ssl_s, "None") == 0)
			test_ssl = 0;
		else if (strcmp(test_ssl_s, "All") == 0)
			test_ssl = 2;
	}
	if (key || cert) {
		if (!key)
			key = cert;
		if (!cert)
			cert = key;
		plug_set_ssl_cert(desc, cert);
		plug_set_ssl_key(desc, key);
	}
	if (pempass != NULL)
		plug_set_ssl_pem_password(desc, pempass);
	if (cafile != NULL)
		plug_set_ssl_CA_file(desc, cafile);
#endif				/* HAVE_SSL */



	signal(SIGTERM, sigterm);
	signal(SIGCHLD, sigchld);
	if (num_sons_s != NULL)
		num_sons = atoi(num_sons_s);

	if (num_sons <= 0)
		num_sons = 10;

	if (num_sons > MAX_SONS)
		num_sons = MAX_SONS;




	for (i = 0; i < num_sons; i++) {
		sons[i] = 0;
		sons_args[i] = NULL;
	}

	if (h == NULL)
		return 1;

	ag = h;

	while (ag->next != NULL) {
		if (strncmp(ag->name, head, strlen(head)) == 0)
			num_ports++;
		ag = ag->next;
	}


	ag = h;

	port_per_son = num_ports / num_sons;


	for (i = 0; i < num_sons; i = i + 1) {
		int             j;

		if (ag->next != NULL) {
			for (j = 0; j < port_per_son && ag->next != NULL;) {
				if (strncmp(ag->name, head, strlen(head)) == 0) {
					if (sons_args[i] == NULL)
						sons_args[i] = emalloc(sizeof(struct arglist));
					arg_add_value(sons_args[i], ag->name, ag->type, ag->length, ag->value);
					j++;
				}
				ag = ag->next;
			}
		} else
			break;
	}


	for (i = 0; (i < num_ports % num_sons) && ag->next != NULL;) {
		if (strncmp(ag->name, head, strlen(head)) == 0) {
			if (sons_args[i] == NULL)
				sons_args[i] = emalloc(sizeof(struct arglist));
			arg_add_value(sons_args[i], ag->name, ag->type, ag->length, ag->value);
			i++;
		}
		ag = ag->next;
	}

	for (i = 0; i < num_sons; i++)
		if (sons_args[i] == NULL)
			break;


	num_sons = i;


	for (i = 0; i < num_sons; i++) {
		usleep(5000);
		if (sons_args[i] != NULL) {
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, sons_pipe[i]) < 0) {
				perror("socketpair ");
				break;
			}
			sons[i] = fork();
			if (sons[i] == 0) {
				int soc = GPOINTER_TO_SIZE(arg_get_value(globals, "global_socket"));
				close(sons_pipe[i][1]);
				close(soc);
				soc = dup2(sons_pipe[i][0], 4);
				close(sons_pipe[i][0]);
				arg_set_value(globals, "global_socket", sizeof(gpointer), GSIZE_TO_POINTER(soc));
				arg_set_value(desc, "SOCKET", sizeof(gpointer), GSIZE_TO_POINTER(soc));
				signal(SIGTERM, _exit);
				plugin_do_run(desc, sons_args[i], test_ssl);
				exit(0);
			} else {
				close(sons_pipe[i][0]);
				if (sons[i] < 0)
					sons[i] = 0;	/* Fork failed */
			}
		}
	}



	for (;;) {
		int             flag = 0;
		fd_set          rd;
		struct timeval  tv;
		int             max = -1;
		int             e;


		FD_ZERO(&rd);
		for (i = 0; i < num_sons; i++) {
			if (sons[i] != 0 && (sons_pipe[i][1] >= 0)) {
				FD_SET(sons_pipe[i][1], &rd);
				if (sons_pipe[i][1] > max)
					max = sons_pipe[i][1];
			}
		}

again:
		tv.tv_usec = 100000;
		tv.tv_sec = 0;
		e = select(max + 1, &rd, NULL, NULL, &tv);
		if (e < 0 && errno == EINTR)
			goto again;

		if (e > 0) {
			for (i = 0; i < num_sons; i++) {
				if (sons[i] != 0 && sons_pipe[i][1] >= 0 && FD_ISSET(sons_pipe[i][1], &rd) != 0) {
					if (fwd_data(sons_pipe[i][1], one_true_pipe, sons[i]) < 0) {
						close(sons_pipe[i][1]);
						sons_pipe[i][1] = -1;
						while (waitpid(sons[i], NULL, WNOHANG) && errno == EINTR);
						sons[i] = 0;
					}
				}
			}
		}
		for (i = 0; i < num_sons; i++) {
			if (sons[i] != 0) {
				while (waitpid(sons[i], NULL, WNOHANG) && errno == EINTR);

				if (kill(sons[i], 0) < 0) {
					fwd_data(sons_pipe[i][1], one_true_pipe, sons[i]);
					close(sons_pipe[i][1]);
					sons_pipe[i][1] = -1;
					sons[i] = 0;
				} else
					flag++;
			}
		}


		if (flag == 0)
			break;
	}

	return 0;
}
