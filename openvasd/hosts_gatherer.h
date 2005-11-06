#ifndef HOSTS_GATHERER_H__
#define HOSTS_GATHERER_H__

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif



#undef DEBUG_HIGH


#define HG_NFS                1 
#define HG_DNS_AXFR           2
#define HG_SUBNET             4
#define HG_PING       	      8
#define HG_REVLOOKUP 	     16  /* Are we allowed to use the DNS ? */
#define HG_REVLOOKUP_AS_PING 32 
#define HG_DISTRIBUTE	     64

struct hg_host {
	char * hostname;	/* Host name                    */
	char * domain;		/* This is the same pointers as */
				/* hostname ! Don't free() it ! */
	struct in_addr addr;	/* Host IP   	        	*/
	int    cidr_netmask;	/* CIDR-format netmask 		*/
	
				/* When given a /N notation, we 
				   put this as the upper limit
				   of the network */
	struct in_addr min;
	struct in_addr max;
	int	use_max:1;	/* use the field above ?	*/
 	unsigned int    tested:1;
	unsigned int    alive:1;
	struct hg_host * next;
	};

struct hg_globals {
	struct hg_host * host_list;    /* List of tested hosts       */
	struct hg_host * tested;       /* Tested subnets and domains */
	int		  flags;       /* options		     */
	char 		* input;
	char 		* marker;
	int	counter;
	unsigned int	distribute;
	};
		 
struct hg_globals * hg_init(char *, int);
int hg_next_host(struct hg_globals *, struct in_addr *, char *, int);
void   hg_cleanup  (struct hg_globals *);
int hg_get_name_from_ip(struct in_addr ip, char *, int);
#endif
