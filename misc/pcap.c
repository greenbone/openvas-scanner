/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1999 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "bpf_share.h"
#include "network.h"
#include "pcap_openvas.h"
#include "support.h"

#include <arpa/inet.h>
#include <errno.h>
#include <gvm/base/logging.h>
#include <gvm/base/networking.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#define MAXROUTES 1024

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/**
 * @brief Maximum length of an interface's name
 */
#define MAX_IFACE_NAME_LEN 64

struct interface_info
{
  char name[MAX_IFACE_NAME_LEN];
  struct in_addr addr;
  struct in6_addr addr6;
  struct in6_addr mask;
};

/**
 * Only used for v6_routethrough() and not routethrough().
 * routethrough() uses a local version of the myroutes struct.
 */
struct myroute
{
  struct interface_info *dev;
  struct in6_addr dest6;
  unsigned long mask;
  unsigned long dest;
  unsigned long metric;
};

struct interface_info *
getinterfaces (int *howmany);
struct interface_info *
v6_getinterfaces (int *howmany);
int
getipv6routes (struct myroute *myroutes, int *numroutes);

/**
 * @brief Generate an ipv6 mask from the given ipv6 prefix.
 *
 * This function is a copy of the function ipv6_prefix_to_mask() obtained from
 * GPL-2.0 licensed https://gitlab.com/ipcalc/ipcalc/-/blob/master/ipcalc.c.
 *
 * @param[in]   prefix  The ipv6 prefix.
 * @param[out]  mask    The mask corresponding to the prefix.
 *
 * @return 0 on success, -1 on error.
 **/
static int
ipv6_prefix_to_mask (unsigned prefix, struct in6_addr *mask)
{
  struct in6_addr in6;
  int i, j;

  if (prefix > 128)
    return -1;

  memset (&in6, 0x0, sizeof (in6));
  for (i = prefix, j = 0; i > 0; i -= 8, j++)
    {
      if (i >= 8)
        {
          in6.s6_addr[j] = 0xff;
        }
      else
        {
          in6.s6_addr[j] = (unsigned long) (0xffU << (8 - i));
        }
    }

  memcpy (mask, &in6, sizeof (*mask));
  return 0;
}

int
v6_is_local_ip (struct in6_addr *addr)
{
  int i, j, ifaces, numroutes = 0;
  struct interface_info *ifs;
  static struct myroute myroutes[MAXROUTES];
  struct in6_addr network, mask;
  bpf_u_int32 v4mappednet, v4mappedmask;

  if ((ifs = v6_getinterfaces (&ifaces)) == NULL)
    return -1;

  if (IN6_IS_ADDR_V4MAPPED (addr))
    {
      for (i = 0; i < ifaces; i++)
        {
          char errbuf[PCAP_ERRBUF_SIZE];
          pcap_lookupnet (ifs[i].name, &v4mappednet, &v4mappedmask, errbuf);
          if ((v4mappednet & v4mappedmask)
              == (addr->s6_addr32[3] & v4mappedmask))
            return 1;
        }
    }
  else
    {
      if (IN6_IS_ADDR_LINKLOCAL (addr))
        return 1;
      if (IN6_IS_ADDR_LOOPBACK (addr))
        return 1;
      if (getipv6routes (myroutes, &numroutes) == 0)
        {
          for (i = 0; i < numroutes; i++)
            {
              char addr1[INET6_ADDRSTRLEN];
              char addr2[INET6_ADDRSTRLEN];

              if (ipv6_prefix_to_mask (myroutes[i].mask, &mask) == -1)
                return -1;
              for (j = 0; j < (int) sizeof (struct in6_addr); j++)
                network.s6_addr[j] = addr->s6_addr[j] & mask.s6_addr[j];

              g_debug ("comparing addresses %s and %s",
                       inet_ntop (AF_INET6, &network, addr1, sizeof (addr1)),
                       inet_ntop (AF_INET6, &myroutes[i].dest6, addr2,
                                  sizeof (addr2)));
              if (IN6_ARE_ADDR_EQUAL (&network, &myroutes[i].dest6))
                {
                  return 1;
                }
            }
        }
    }
  return 0;
}

/*
 * Taken straight out of Fyodor's Nmap
 */
static int
v6_ipaddr2devname (char *dev, int sz, struct in6_addr *addr)
{
  struct interface_info *mydevs;
  int numdevs = 0;
  int i;
  mydevs = v6_getinterfaces (&numdevs);

  if (!mydevs)
    return -1;

  for (i = 0; i < numdevs; i++)
    {
      char addr1[INET6_ADDRSTRLEN];
      char addr2[INET6_ADDRSTRLEN];
      g_debug ("comparing addresses %s and %s",
               inet_ntop (AF_INET6, addr, addr1, sizeof (addr1)),
               inet_ntop (AF_INET6, &mydevs[i].addr6, addr2, sizeof (addr2)));
      if (IN6_ARE_ADDR_EQUAL (addr, &mydevs[i].addr6))
        {
          dev[sz - 1] = '\0';
          strncpy (dev, mydevs[i].name, sz);
          return 0;
        }
    }
  return -1;
}

/*
 * Taken straight out of Fyodor's Nmap
 */
static int
ipaddr2devname (char *dev, int sz, struct in_addr *addr)
{
  struct interface_info *mydevs;
  int numdevs;
  int i;
  mydevs = getinterfaces (&numdevs);

  if (!mydevs)
    return -1;

  for (i = 0; i < numdevs; i++)
    {
      if (addr->s_addr == mydevs[i].addr.s_addr)
        {
          dev[sz - 1] = '\0';
          strncpy (dev, mydevs[i].name, sz);
          return 0;
        }
    }
  return -1;
}

/**
 * @brief Tests whether a packet sent to IP is LIKELY to route through the
 * kernel localhost interface
 */
int
v6_islocalhost (struct in6_addr *addr)
{
  char dev[128];

  if (addr == NULL)
    return -1;

  if (IN6_IS_ADDR_V4MAPPED (addr))
    {
      /* If it is 0.0.0.0 or starts with 127.0.0.1 then it is
         probably localhost */
      if ((addr->s6_addr32[3] & htonl (0xFF000000)) == htonl (0x7F000000))
        return 1;

      if (!addr->s6_addr32[3])
        return 1;
    }

  if (IN6_IS_ADDR_LOOPBACK (addr))
    return 1;

  /* If it is the same addy as a local interface, then it is
     probably localhost */

  if (v6_ipaddr2devname (dev, sizeof (dev), addr) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}

/**
 * @brief Tests whether a packet sent to IP is LIKELY to route through the
 * kernel localhost interface
 */
int
islocalhost (struct in_addr *addr)
{
  char dev[128];

  if (addr == NULL)
    return -1;

  /* If it is 0.0.0.0 or starts with 127.0.0.1 then it is
     probably localhost */
  if ((addr->s_addr & htonl (0xFF000000)) == htonl (0x7F000000))
    return 1;

  if (!addr->s_addr)
    return 1;

  /* If it is the same addy as a local interface, then it is
     probably localhost */

  if (ipaddr2devname (dev, sizeof (dev), addr) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}

int
get_datalink_size (int datalink)
{
  int offset = -1;
  switch (datalink)
    {
    case DLT_EN10MB:
      offset = 14;
      break;
    case DLT_IEEE802:
      offset = 22;
      break;
    case DLT_NULL:
      offset = 4;
      break;
    case DLT_SLIP:
#if (FREEBSD || OPENBSD || NETBSD || BSDI || DARWIN)
      offset = 16;
#else
      offset = 24; /* Anyone use this??? */
#endif
      break;
    case DLT_PPP:
#if (FREEBSD || OPENBSD || NETBSD || BSDI || DARWIN)
      offset = 4;
#else
#ifdef SOLARIS
      offset = 8;
#else
      offset = 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
      break;
    case DLT_RAW:
      offset = 0;
      break;
    }
  return (offset);
}

struct interface_info *
v6_getinterfaces (int *howmany)
{
  struct sockaddr_in *saddr;
  struct sockaddr_in6 *s6addr;
  static struct interface_info mydevs[1024];
  int numinterfaces = 0;
  struct ifaddrs *ifaddr, *ifa;
  int family;

  if (getifaddrs (&ifaddr) == -1)
    {
      perror ("getifaddrs");
    }
  else
    {
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if (ifa->ifa_addr == NULL)
            continue;

          family = ifa->ifa_addr->sa_family;
          if (family == AF_INET)
            {
              strncpy (mydevs[numinterfaces].name, ifa->ifa_name,
                       sizeof (mydevs[numinterfaces].name) - 1);
              saddr = (struct sockaddr_in *) ifa->ifa_addr;
              mydevs[numinterfaces].addr6.s6_addr32[0] = 0;
              mydevs[numinterfaces].addr6.s6_addr32[1] = 0;
              mydevs[numinterfaces].addr6.s6_addr32[2] = htonl (0xffff);
              mydevs[numinterfaces].addr6.s6_addr32[3] = saddr->sin_addr.s_addr;
              saddr = (struct sockaddr_in *) ifa->ifa_netmask;
              mydevs[numinterfaces].mask.s6_addr32[0] = 0;
              mydevs[numinterfaces].mask.s6_addr32[1] = 0;
              mydevs[numinterfaces].mask.s6_addr32[2] = htonl (0xffff);
              mydevs[numinterfaces].mask.s6_addr32[3] = saddr->sin_addr.s_addr;
              g_debug ("interface name is %s", ifa->ifa_name);
              g_debug ("\tAF_INET family");
              g_debug ("\taddress is %s", inet_ntoa (saddr->sin_addr));
              g_debug ("\tnetmask is %s", inet_ntoa (saddr->sin_addr));
              numinterfaces++;
            }
          else if (family == AF_INET6)
            {
              char ipaddr[INET6_ADDRSTRLEN];

              strncpy (mydevs[numinterfaces].name, ifa->ifa_name,
                       sizeof (mydevs[numinterfaces].name) - 1);
              s6addr = (struct sockaddr_in6 *) ifa->ifa_addr;
              memcpy (&(mydevs[numinterfaces].addr6),
                      (char *) &(s6addr->sin6_addr), sizeof (struct in6_addr));
              s6addr = (struct sockaddr_in6 *) ifa->ifa_netmask;
              memcpy (&(mydevs[numinterfaces].mask),
                      (char *) &(s6addr->sin6_addr), sizeof (struct in6_addr));
              numinterfaces++;
              g_debug ("\tAF_INET6 family");
              g_debug ("interface name is %s", ifa->ifa_name);
              g_debug ("\taddress is %s",
                       inet_ntop (AF_INET6, &s6addr->sin6_addr, ipaddr,
                                  sizeof (ipaddr)));
            }
          else
            g_debug ("\tfamily is %d", ifa->ifa_addr->sa_family);
        }
      *howmany = numinterfaces;

      freeifaddrs (ifaddr);
    }
  return mydevs;
}

/**
 * @param[out] howmany Return location for the number of interfaces found
 *                     (might be NULL).
 */
struct interface_info *
getinterfaces (int *howmany)
{
  static struct interface_info mydevs[1024];
  int numinterfaces = 0;
  int sd;
  int len;
  char *p;
  char buf[10240];
  struct ifconf ifc;
  struct ifreq *ifr;
  struct sockaddr_in *sin;
  char *bufp;

  /* Dummy socket for ioctl. */
  sd = socket (AF_INET, SOCK_DGRAM, 0);
  bzero (buf, sizeof (buf));
  if (sd < 0)
    {
      g_message ("socket in getinterfaces");
      return NULL;
    }

  ifc.ifc_len = sizeof (buf);
  ifc.ifc_buf = buf;
  if (ioctl (sd, SIOCGIFCONF, &ifc) < 0)
    g_message ("Failed to determine your configured interfaces!");

  close (sd);
  if (ifc.ifc_len == 0)
    g_message (
      "getinterfaces: SIOCGIFCONF claims you have no network interfaces!");

#ifndef __FreeBSD__
  len = sizeof (struct ifmap);
#else
  len = sizeof (struct sockaddr);
#endif

  for (bufp = buf; bufp && *bufp && (bufp < (buf + ifc.ifc_len));
       bufp += sizeof (ifr->ifr_name) + len)
    {
      ifr = (struct ifreq *) bufp;
      sin = (struct sockaddr_in *) &ifr->ifr_addr;
      memcpy (&(mydevs[numinterfaces].addr), (char *) &(sin->sin_addr),
              sizeof (struct in_addr));
      /* In case it is a stinkin' alias */
      if ((p = strchr (ifr->ifr_name, ':')))
        *p = '\0';

      memset (mydevs[numinterfaces].name, '\0', MAX_IFACE_NAME_LEN);
      if (strlen (ifr->ifr_name) < MAX_IFACE_NAME_LEN)
        memcpy (mydevs[numinterfaces].name, ifr->ifr_name,
                strlen (ifr->ifr_name));
      else
        memcpy (mydevs[numinterfaces].name, ifr->ifr_name,
                MAX_IFACE_NAME_LEN - 1);
      numinterfaces++;
      if (numinterfaces == 1023)
        {
          g_message ("You seem to have more than 1023 network interfaces."
                     " Things may not work right.");
          break;
        }
      mydevs[numinterfaces].name[0] = '\0';
    }

  // If output parameter given, set value
  if (howmany)
    *howmany = numinterfaces;

  return mydevs;
}

int
v6_getsourceip (struct in6_addr *src, struct in6_addr *dst)
{
  int sd;
  struct sockaddr_in sock;
  unsigned int socklen;
  unsigned short p1;

  p1 = (unsigned short) rand ();
  if (p1 < 5000)
    p1 += 5000;

  if (IN6_IS_ADDR_V4MAPPED (dst))
    {
      char name[INET6_ADDRSTRLEN];

      if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) == -1)
        {
          perror ("Socket troubles");
          return 0;
        }
      bzero (&sock, sizeof (struct sockaddr_in));
      sock.sin_family = AF_INET;
      sock.sin_addr.s_addr = dst->s6_addr32[3];
      sock.sin_port = htons (p1);
      if (connect (sd, (struct sockaddr *) &sock, sizeof (struct sockaddr_in))
          == -1)
        {
          close (sd);
          return 0;
        }
      bzero (&sock, sizeof (struct sockaddr_in));
      socklen = sizeof (struct sockaddr_in);
      if (getsockname (sd, (struct sockaddr *) &sock, &socklen) == -1)
        {
          perror ("getsockname");
          close (sd);
          return 0;
        }

      src->s6_addr32[0] = 0;
      src->s6_addr32[1] = 0;
      src->s6_addr32[2] = htonl (0xffff);
      src->s6_addr32[3] = sock.sin_addr.s_addr;
      g_debug ("source address is %s",
               inet_ntop (AF_INET6, src, name, sizeof (name)));
      close (sd);
    }
  else
    {
      struct sockaddr_in6 sock6;
      char name[INET6_ADDRSTRLEN];

      if ((sd = socket (AF_INET6, SOCK_DGRAM, 0)) == -1)
        {
          perror ("Socket troubles");
          return 0;
        }
      bzero (&sock6, sizeof (sock6));
      sock6.sin6_family = AF_INET6;
      sock6.sin6_addr.s6_addr32[0] = dst->s6_addr32[0];
      sock6.sin6_addr.s6_addr32[1] = dst->s6_addr32[1];
      sock6.sin6_addr.s6_addr32[2] = dst->s6_addr32[2];
      sock6.sin6_addr.s6_addr32[3] = dst->s6_addr32[3];
      sock6.sin6_port = htons (p1);
      if (connect (sd, (struct sockaddr *) &sock6, sizeof (struct sockaddr_in6))
          == -1)
        {
          close (sd);
          return 0;
        }
      bzero (&sock6, sizeof (struct sockaddr_in6));
      socklen = sizeof (struct sockaddr_in6);
      if (getsockname (sd, (struct sockaddr *) &sock6, &socklen) == -1)
        {
          perror ("getsockname");
          close (sd);
          return 0;
        }

      src->s6_addr32[0] = sock6.sin6_addr.s6_addr32[0];
      src->s6_addr32[1] = sock6.sin6_addr.s6_addr32[1];
      src->s6_addr32[2] = sock6.sin6_addr.s6_addr32[2];
      src->s6_addr32[3] = sock6.sin6_addr.s6_addr32[3];
      memcpy (src, &sock6.sin6_addr, sizeof (struct in6_addr));
      g_debug ("source addrss is %s",
               inet_ntop (AF_INET6, src, name, sizeof (name)));
      close (sd);
    }
  return 1; /* Calling function responsible for checking validity */
}

/**
 * @brief Get the ipv4 routes and number of routes.
 *
 * This function is only used for getting the ipv4 routes in v6_routethrough().
 * routethrough() overwrites the global myroutes struct with a local version
 * and uses its own logic for getting the routes from /proc/net/route.
 *
 * @param[out] myroutes Array of routes.
 * @param[out] numroutes Number of routes in myroutes.
 *
 * @return 0 on success, -1 on error.
 **/
static int
getipv4routes (struct myroute *myroutes, int *numroutes)
{
  struct interface_info *mydevs;
  int i;
  int numinterfaces;
  char buf[1024];
  char *p, *endptr;
  char iface[MAX_IFACE_NAME_LEN];
  FILE *routez;
  unsigned long dest;
  struct in_addr inaddr;
  unsigned long mask;
  unsigned long ones;

  /* Dummy socket for ioctl */
  mydevs = v6_getinterfaces (&numinterfaces);

  /* Now we must go through several techniques to determine info */
  routez = fopen ("/proc/net/route", "r");

  if (routez)
    {
      /* OK, linux style /proc/net/route ... we can handle this ... */
      /* Now that we've got the interfaces, we g0 after the r0ut3Z */
      if (fgets (buf, sizeof (buf), routez) == NULL) /* Kill the first line */
        {
          // /proc/net/route was empty or an error occurred.
          g_message ("Could not read from /proc/net/route");
          fclose (routez);
          return -1;
        }
      while (fgets (buf, sizeof (buf), routez))
        {
          p = strtok (buf, " \t\n");
          if (!p)
            {
              g_message ("Could not find interface in"
                         " /proc/net/route line");
              continue;
            }
          strncpy (iface, p, sizeof (iface));
          iface[MAX_IFACE_NAME_LEN - 1] = '\0';
          if ((p = strchr (iface, ':')))
            {
              *p = '\0'; /* To support IP aliasing */
            }
          p = strtok (NULL, " \t\n");
          endptr = NULL;
          dest = strtoul (p, &endptr, 16);
          g_debug ("ipv4 dest is %s", p);
          if (!endptr || *endptr)
            {
              g_message ("Failed to determine Destination from"
                         " /proc/net/route");
              continue;
            }
          inaddr.s_addr = dest;
          myroutes[*numroutes].dest6.s6_addr32[0] = 0;
          myroutes[*numroutes].dest6.s6_addr32[1] = 0;
          myroutes[*numroutes].dest6.s6_addr32[2] = htonl (0xffff);
          myroutes[*numroutes].dest6.s6_addr32[3] = inaddr.s_addr;
          for (i = 0; i < 5; i++)
            {
              p = strtok (NULL, " \t\n");
              if (!p)
                break;
            }
          if (!p)
            {
              g_message ("Failed to find field %d in"
                         " /proc/net/route",
                         i + 2);
              continue;
            }
          /* set metric */
          endptr = NULL;
          myroutes[*numroutes].metric = strtol (p, &endptr, 10);
          if (!endptr || *endptr)
            {
              g_message ("%s: Failed to determine metric from /proc/net/route",
                         __func__);
              continue;
            }
          p = strtok (NULL, " \t\n");
          endptr = NULL;
          mask = strtoul (p, &endptr, 16);
          ones = 0;
          i = 0;
          while (mask & (1 << i++) && i < 32)
            ones++;
          myroutes[*numroutes].mask = ones + 96;
          g_debug ("mask is %lu", myroutes[*numroutes].mask);
          if (!endptr || *endptr)
            {
              g_message ("Failed to determine mask from"
                         " /proc/net/route");
              continue;
            }

          g_debug ("#%d: for dev %s, The dest is %lX and the mask is %lX",
                   *numroutes, iface, myroutes[*numroutes].dest,
                   myroutes[*numroutes].mask);
          for (i = 0; i < numinterfaces; i++)
            if (!strcmp (iface, mydevs[i].name))
              {
                myroutes[*numroutes].dev = &mydevs[i];
                break;
              }
          if (i == numinterfaces)
            g_message (
              "Failed to find interface %s mentioned in /proc/net/route",
              iface);
          (*numroutes)++;
          if (*numroutes >= MAXROUTES)
            {
              g_message ("You seem to have WAY to many routes!");
              break;
            }
        }
      fclose (routez);
      return 0;
    }
  else
    return -1;
}

/**
 * @brief Get the IPv6 routes and number of routes.
 *
 * This function parses the /proc/net/ipv6_route file into an array of
 * myroute structs.
 *
 * @param[out] myroutes Array of routes.
 * @param[out] numroutes Number of routes in myroutes.
 *
 * @return 0 on success, -1 when no routes are found.
 */
int
getipv6routes (struct myroute *myroutes, int *numroutes)
{
  struct interface_info *mydevs;
  int i, j;
  int len;
  struct in6_addr in6addr;
  char destaddr[100];
  int numinterfaces;
  char buf[1024];
  char *endptr;
  FILE *routez;
  char v6addr[INET6_ADDRSTRLEN];
  char *token;
  int cnt;

  /* Dummy socket for ioctl */
  mydevs = v6_getinterfaces (&numinterfaces);
  routez = fopen ("/proc/net/ipv6_route", "r");
  if (routez)
    {
      /* linux style /proc/net/ipv6_route ... we can handle this too... */
      while (fgets (buf, sizeof (buf), routez) != NULL)
        {
          char iface[64];

          token = strtok (buf, " \t\n");
          if (token)
            {
              g_debug ("first token is %s", token);
              strncpy (destaddr, token, sizeof (destaddr) - 1);
              len = strlen (destaddr);
              for (i = 0, j = 0; j < len; j++)
                {
                  v6addr[i++] = destaddr[j];
                  if (j % 4 == 3)
                    v6addr[i++] = ':';
                }
              v6addr[--i] = '\0';
              g_debug ("ipv6 dest is %s", v6addr);
              if (inet_pton (AF_INET6, v6addr, &in6addr) <= 0)
                {
                  g_message ("invalid ipv6 addressd");
                  continue;
                }
              memcpy (&myroutes[*numroutes].dest6, &in6addr,
                      sizeof (struct in6_addr));
            }
          token = strtok (NULL, " \t\n");
          if (token)
            {
              endptr = NULL;
              myroutes[*numroutes].mask = strtoul (token, &endptr, 16);
            }

          /* set metric */
          cnt = 4;
          while (cnt--)
            {
              token = strtok (NULL, " \t\n");
              if (!token)
                g_message ("getipv6routes error");
            }
          endptr = NULL;
          myroutes[*numroutes].metric = strtoul (token, &endptr, 16);
          if (!endptr || *endptr)
            {
              g_message (
                "%s: Failed to determine metric from /proc/net/ipv6_route",
                __func__);
              continue;
            }

          /* set interface name */
          cnt = 3;
          while (cnt--)
            {
              token = strtok (NULL, " \t\n");
              if (!token)
                g_message ("getipv6routes error");
            }
          bzero (iface, sizeof (iface));
          token = strtok (NULL, " \t\n");
          if (token)
            strncpy (iface, token, sizeof (iface) - 1);
          for (i = 0; i < numinterfaces; i++)
            if (!strcmp (iface, mydevs[i].name)
                && !IN6_IS_ADDR_V4MAPPED (&mydevs[i].addr6))
              {
                myroutes[*numroutes].dev = &mydevs[i];
                break;
              }
          if (i == numinterfaces)
            g_message (
              "Failed to find interface %s mentioned in /proc/net/ipv6_route",
              iface);
          (*numroutes)++;
          if (*numroutes >= MAXROUTES)
            {
              g_message ("You seem to have WAY to many routes!");
              break;
            }
        }
      fclose (routez);
      return 0;
    }
  else
    {
      g_message ("Didn't find IPv6 routes");
      return -1;
    }
}

/** @brief An awesome function to determine what interface a packet to a given
 *  destination should be routed through.
 *
 * It returns NULL if no appropriate
 *  interface is found, otherwise it returns the device name and fills in the
 *   source parameter.   Some of the stuff is
 *  from Stevens' Unix Network Programming V2.  He had an easier suggestion
 *  for doing this (in the book), but it isn't portable :(
 */
char *
v6_routethrough (struct in6_addr *dest, struct in6_addr *source)
{
  static int initialized = 0;
  int i;
  struct in6_addr addy;
  static enum {
    procroutetechnique,
    connectsockettechnique,
    guesstechnique
  } technique = procroutetechnique;
  struct interface_info *mydevs;
  static struct myroute myroutes[MAXROUTES];
  int numinterfaces = 0;
  static int numroutes = 0;
  struct in6_addr mask;
  struct in6_addr network = {0};
  struct in6_addr src;
  long best_match = -1;

  if (!dest)
    {
      g_message ("ipaddr2devname passed a NULL dest address");
      return NULL;
    }

  if (IN6_IS_ADDR_V4MAPPED (dest))
    gvm_source_addr_as_addr6 (&src);
  else
    gvm_source_addr6 (&src);

  if (!initialized)
    {
      /* Dummy socket for ioctl */
      initialized = 1;
      mydevs = v6_getinterfaces (&numinterfaces);
      if (IN6_IS_ADDR_V4MAPPED (dest))
        {
          if (getipv4routes (myroutes, &numroutes) < 0)
            technique = connectsockettechnique;
        }
      else
        {
          if (getipv6routes (myroutes, &numroutes) < 0)
            technique = connectsockettechnique;
        }
    }
  else
    {
      mydevs = v6_getinterfaces (&numinterfaces);
    }
  /* WHEW, that takes care of initializing, now we have the easy job of
     finding which route matches */
  if (v6_islocalhost (dest))
    {
      if (source)
        {
          if (IN6_IS_ADDR_V4MAPPED (source))
            {
              source->s6_addr32[0] = 0;
              source->s6_addr32[1] = 0;
              source->s6_addr32[2] = htonl (0xffff);
              source->s6_addr32[3] = htonl (0x7F000001);
            }
          else
            {
              source->s6_addr32[0] = 0;
              source->s6_addr32[1] = 0;
              source->s6_addr32[2] = 0;
              source->s6_addr32[3] = htonl (1);
            }
        }
      /* Now we find the localhost interface name, assuming 127.0.0.1
         or ::1 is localhost (it damn well better be!)... */
      for (i = 0; i < numinterfaces; i++)
        {
          if (IN6_IS_ADDR_V4MAPPED (&mydevs[i].addr6))
            {
              if (mydevs[i].addr6.s6_addr32[3] == htonl (0x7F000001))
                return mydevs[i].name;
            }
          else
            {
              if (IN6_ARE_ADDR_EQUAL (&in6addr_any, &mydevs[i].addr6))
                return mydevs[i].name;
            }
        }
      return NULL;
    }

  if (technique == procroutetechnique)
    {
      char addr1[INET6_ADDRSTRLEN];
      char addr2[INET6_ADDRSTRLEN];
      for (i = 0; i < numroutes; i++)
        {
          if (ipv6_prefix_to_mask (myroutes[i].mask, &mask) == -1)
            {
              g_warning ("error creating IPv6 mask from prefix: %ld",
                         myroutes[i].mask);
              return NULL;
            }
          for (int j = 0; j < (int) sizeof (struct in6_addr); j++)
            network.s6_addr[j] = dest->s6_addr[j] & mask.s6_addr[j];

          g_debug (
            "comparing addresses %s and %s",
            inet_ntop (AF_INET6, &network, addr1, sizeof (addr1)),
            inet_ntop (AF_INET6, &myroutes[i].dest6, addr2, sizeof (addr2)));
          /* matching route found */
          if (IN6_ARE_ADDR_EQUAL (&network, &myroutes[i].dest6))
            {
              /* First time a match is found */
              if (-1 == best_match)
                {
                  best_match = i;
                }
              else
                {
                  /* Better match found */
                  if (myroutes[i].mask > myroutes[best_match].mask)
                    {
                      best_match = i;
                    }
                  /* Match with equal mask and smaller (better) metric found */
                  else if ((myroutes[i].mask == myroutes[best_match].mask)
                           && (myroutes[i].metric
                               < myroutes[best_match].metric))
                    {
                      best_match = i;
                    }
                }
            }
        }
      if (source)
        {
          if (!IN6_ARE_ADDR_EQUAL (&src, &in6addr_any))
            memcpy (source, &src, sizeof (struct in6_addr));
          else
            {
              if (myroutes[best_match].dev != NULL)
                {
                  memcpy (source, &myroutes[best_match].dev->addr6,
                          sizeof (struct in6_addr));
                }
            }
        }
      g_debug (
        "%s: Best matching route with dst '%s' metric '%ld' and interface '%s'",
        __func__,
        inet_ntop (AF_INET6, &myroutes[best_match].dest6, addr1,
                   sizeof (addr1)),
        myroutes[best_match].mask, myroutes[best_match].dev->name);
      if (best_match != -1)
        return myroutes[best_match].dev->name;

      technique = connectsockettechnique;
    }
  if (technique == connectsockettechnique)
    {
      if (!v6_getsourceip (&addy, dest))
        return NULL;
      if (IN6_ARE_ADDR_EQUAL (&addy, &network))
        {
          struct hostent *myhostent = NULL;
          char myname[MAXHOSTNAMELEN + 1];

          myhostent = gethostbyname (myname);
          if (gethostname (myname, MAXHOSTNAMELEN) || !myhostent)
            g_message ("Cannot get hostname!");
          else if (myhostent->h_addrtype == AF_INET)
            {
              addy.s6_addr32[0] = 0;
              addy.s6_addr32[1] = 0;
              addy.s6_addr32[2] = htonl (0xffff);
              memcpy (&addy.s6_addr32[0], myhostent->h_addr_list[0],
                      sizeof (struct in6_addr));
            }
          else
            memcpy (&addy, myhostent->h_addr_list[0], sizeof (struct in6_addr));
        }

      /* Now we insure this claimed address is a real interface ... */
      for (i = 0; i < numinterfaces; i++)
        {
          char addr1[INET6_ADDRSTRLEN];
          char addr2[INET6_ADDRSTRLEN];

          g_debug (
            "comparing addresses %s and %s",
            inet_ntop (AF_INET6, &mydevs[i].addr6, addr1, sizeof (addr1)),
            inet_ntop (AF_INET6, &addy, addr2, sizeof (addr2)));
          if (IN6_ARE_ADDR_EQUAL (&mydevs[i].addr6, &addy))
            {
              if (source)
                {
                  memcpy (source, &addy, sizeof (struct in6_addr));
                }
              return mydevs[i].name;
            }
        }
      return NULL;
    }
  else
    g_message ("%s: Provided technique is neither proc route nor"
               " connect socket",
               __func__);
  return NULL;
}

/** @brief An awesome function to determine what interface a packet to a given
 *  destination should be routed through.
 *
 * It returns NULL if no appropriate
 *  interface is found, otherwise it returns the device name and fills in the
 *   source parameter.   Some of the stuff is
 *  from Stevens' Unix Network Programming V2.  He had an easier suggestion
 *  for doing this (in the book), but it isn't portable :(
 */
char *
routethrough (struct in_addr *dest, struct in_addr *source)
{
  static int initialized = 0;
  int i;
  char buf[10240];
  struct interface_info *mydevs;
  static struct myroute
  {
    struct interface_info *dev;
    unsigned long mask;
    unsigned long dest;
    unsigned long metric;
  } myroutes[MAXROUTES];
  int numinterfaces = 0;
  char *p, *endptr;
  char iface[MAX_IFACE_NAME_LEN];
  static int numroutes = 0;
  FILE *routez;
  long best_match = -1;

  struct in_addr src;

  gvm_source_addr (&src);
  if (!dest)
    {
      g_message ("ipaddr2devname passed a NULL dest address");
      return NULL;
    }

  if (!initialized)
    {
      /* Dummy socket for ioctl */
      initialized = 1;
      mydevs = getinterfaces (&numinterfaces);
      if (!mydevs)
        return NULL;

      routez = fopen ("/proc/net/route", "r");
      if (routez)
        {
          /* OK, linux style /proc/net/route ... we can handle this ... */
          /* Now that we've got the interfaces, we g0 after the r0ut3Z */
          if (fgets (buf, sizeof (buf), routez)
              == NULL) /* Kill the first line */
            g_message ("Could not read from /proc/net/route");
          while (fgets (buf, sizeof (buf), routez))
            {
              p = strtok (buf, " \t\n");
              if (!p)
                {
                  g_message ("Could not find interface in"
                             " /proc/net/route line");
                  continue;
                }
              strncpy (iface, p, sizeof (iface));
              iface[MAX_IFACE_NAME_LEN - 1] = '\0';
              if ((p = strchr (iface, ':')))
                {
                  *p = '\0'; /* To support IP aliasing */
                }
              p = strtok (NULL, " \t\n");
              endptr = NULL;
              myroutes[numroutes].dest = strtoul (p, &endptr, 16);
              if (!endptr || *endptr)
                {
                  g_message (
                    "Failed to determine Destination from /proc/net/route");
                  continue;
                }
              for (i = 0; i < 5; i++)
                {
                  p = strtok (NULL, " \t\n");
                  if (!p)
                    break;
                }
              if (!p)
                {
                  g_message ("Failed to find field %d in"
                             " /proc/net/route",
                             i + 2);
                  continue;
                }
              endptr = NULL;
              myroutes[numroutes].metric = strtol (p, &endptr, 10);
              if (!endptr || *endptr)
                {
                  g_message ("Failed to determine metric from /proc/net/route");
                  continue;
                }
              p = strtok (NULL, " \t\n");
              endptr = NULL;
              myroutes[numroutes].mask = strtoul (p, &endptr, 16);
              if (!endptr || *endptr)
                {
                  g_message ("Failed to determine mask"
                             " from /proc/net/route");
                  continue;
                }

              g_debug ("#%d: for dev %s, The dest is %lX and the mask is %lX",
                       numroutes, iface, myroutes[numroutes].dest,
                       myroutes[numroutes].mask);
              for (i = 0; i < numinterfaces; i++)
                if (!strcmp (iface, mydevs[i].name))
                  {
                    myroutes[numroutes].dev = &mydevs[i];
                    break;
                  }
              if (i == numinterfaces)
                g_message (
                  "Failed to find interface %s mentioned in /proc/net/route",
                  iface);
              numroutes++;
              if (numroutes >= MAXROUTES)
                {
                  g_message ("You seem to have WAY to many routes!");
                  break;
                }
            }
          fclose (routez);
        }
      else
        {
          g_message ("Could not read from /proc/net/route");
          return NULL;
        }
    }
  else
    mydevs = getinterfaces (&numinterfaces);
  /* WHEW, that takes care of initializing, now we have the easy job of
     finding which route matches */
  if (mydevs && islocalhost (dest))
    {
      if (source)
        source->s_addr = htonl (0x7F000001);
      /* Now we find the localhost interface name, assuming 127.0.0.1 is
         localhost (it damn well better be!)... */
      for (i = 0; i < numinterfaces; i++)
        {
          if (mydevs[i].addr.s_addr == htonl (0x7F000001))
            {
              return mydevs[i].name;
            }
        }
      return NULL;
    }

  for (i = 0; i < numroutes; i++)
    {
      /* Matching route found */
      if ((dest->s_addr & myroutes[i].mask) == myroutes[i].dest)
        {
          /* First time a match is found */
          if (-1 == best_match)
            {
              best_match = i;
            }
          else
            {
              /* Better match found */
              if (myroutes[i].mask > myroutes[best_match].mask)
                {
                  best_match = i;
                }
              /* Match with equal mask and smaller (better) metric found */
              else if ((myroutes[i].mask == myroutes[best_match].mask)
                       && (myroutes[i].metric < myroutes[best_match].metric))
                {
                  best_match = i;
                }
            }
        }
    }

  /* Set source */
  if (source)
    {
      /* Source address is given */
      if (src.s_addr != INADDR_ANY)
        source->s_addr = src.s_addr;
      /* Source address is INADDR_ANY and there is a good route */
      else if (best_match != -1)
        source->s_addr = myroutes[best_match].dev->addr.s_addr;
      /* No best route found and no default */
      else
        {
          /* Assigned first route in the table */
          if (myroutes[0].dev)
            {
              source->s_addr = myroutes[0].dev->addr.s_addr;
              best_match = 0;
            }
          /* or any */
          else
            source->s_addr = INADDR_ANY;
        }
    }

  if (best_match != -1)
    return myroutes[best_match].dev->name;
  return NULL;
}

/** @brief Given an IP address, determines which interface belongs to.
 *
 * @param local_ip IP address.
 *
 * @return Iface name if found, Null otherwise.
 */
char *
get_iface_from_ip (const char *local_ip)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp1 = NULL, *devs_aux = NULL;
  char *if_name = NULL;

  if (pcap_findalldevs (&alldevsp1, errbuf) == -1)
    g_debug ("Error for pcap_findalldevs(): %s", errbuf);

  devs_aux = alldevsp1;
  while (devs_aux)
    {
      pcap_addr_t *addr_aux = NULL;

      addr_aux = devs_aux->addresses;
      while (addr_aux)
        {
          char buffer[INET6_ADDRSTRLEN];

          if (((struct sockaddr *) addr_aux->addr)->sa_family == AF_INET)
            inet_ntop (AF_INET,
                       &(((struct sockaddr_in *) addr_aux->addr)->sin_addr),
                       buffer, INET_ADDRSTRLEN);
          else if (((struct sockaddr *) addr_aux->addr)->sa_family == AF_INET6)
            inet_ntop (AF_INET6,
                       &(((struct sockaddr_in6 *) addr_aux->addr)->sin6_addr),
                       buffer, INET6_ADDRSTRLEN);

          if (!g_strcmp0 (buffer, local_ip))
            {
              if_name = g_strdup (devs_aux->name);
              break;
            }
          addr_aux = addr_aux->next;
        }

      if (if_name)
        break;
      devs_aux = devs_aux->next;
    }
  pcap_freealldevs (alldevsp1);
  g_debug ("returning %s as device", if_name);

  return if_name;
}

/** @brief Get the interface index depending on the target's IP
 *
 * @param[in] ipaddr The ip address of the target.
 * @param[out] ifindex the index of the selected iface
 *
 * @return 0 on success, otherwise -1.
 */
int
get_iface_index (struct in6_addr *ipaddr, int *ifindex)
{
  struct in6_addr src_addr;
  char *if_name, *ip_address;

  // We get the local address to use, with the remote address.
  memset (&src_addr, '\0', sizeof (struct in6_addr));
  v6_getsourceip (&src_addr, ipaddr);
  ip_address = addr6_as_str (&src_addr);

  // Once with the local ip address, we get the source iface name
  if_name = get_iface_from_ip (ip_address);
  g_free (ip_address);
  if (!if_name)
    {
      g_debug ("%s: Missing interface name", __func__);
      return -1;
    }

  *ifindex = if_nametoindex (if_name);

  return 0;
}
