/*
 * Nessus Development Header
 */

#ifndef NESSUSNT

#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy ((s), (d), (n))
#define memmove(d, s, n) bcopy ((s), (d), (n))
#endif

#endif


#if !defined(HAVE_BZERO) || (HAVE_BZERO == 0)
#define bzero(s,z) memset(s,0,z)
#endif

#if !defined(HAVE_BCOPY) || (HAVE_BCOPY == 0)
#define bcopy(x,y,z) memcpy(y,x,z)
#endif

typedef struct {
  int ntp_version;	/*  NTP_VERSION, as defined in ntp.h      	  */
  int ciphered:1;		/*  TRUE, if we are using encryption      	  */
  int ntp_11:1;		/*  TRUE, if we may use NTP 1.1 features; should
			    better be splitted into different capability
			    attributes, but this one simplifies the step
			    from NTP 1.1 to NTP 1.2. In the future we'll
			    use caps, I promise! :-)			  */
  int scan_ids:1;         /*  TRUE, if HOLE and INFO messages should
			    contain scan ID's.				  */
  int pubkey_auth:1;	/* TRUE if the client wants to use public key
  			    authentification */
  int escape_crlf:1;	/* TRUE if the client wants us to escape CRLF
  			   (they will be replaced by ';' if set to FALSE)
			   */

  int md5_caching:1;	/* TRUE if the client does not want us to send the
			   list of plugins directly, but just the md5 
			   hash instead
			 */
			 
  int plugins_version:1;	/* TRUE if the client wants us to send the versions
  			   of our plugins
			 */			 

  int timestamps:1;	/* TRUE if the client wants us to send timestamps
			   regarding the start and end of the whole scan
			   and of each server (msg TIME)
			 */
  int plugins_cve_id:1;	/* the the CVE ID of the plugins along with their version */

  int dns:1; /* send the host name and host ip */
  int dependencies:1; /* send the list of plugins dependencies */
  int fast_login:1;
  int md5_by_name:1;
  int plugins_bugtraq_id:1;
  int plugins_xrefs:1;
} ntp_caps;


