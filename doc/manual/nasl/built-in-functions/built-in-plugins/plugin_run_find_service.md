# plugin_run_find_service

## NAME

**plugin_run_find_service** - find services that are accessible on the target system

## SYNOPSIS

*void* **plugin_run_find_service**();

**plugin_run_find_service** takes no arguments.


## DESCRIPTION

This function is a built-in plugin, which scans the target for any accessible services.

This function will fork for every vHost on the target and scans the whole port range (1-65535). These ports are split between a configurable number of child processes (default is 6). For each port it is then checked if there is a service running. For almost every found service a result of type INFO is generated and the key `Service/\[port\]` is set to its port and the key `Known/tcp/[port]` is set to an identification name. For some services additionally the server banner is saved at `[name]/banner/[port]`.

To detect the services this function tries to get some information first:
1. Any raw data of a banner saved on the currently scanned port, which is saved at `BannerHex/[port]`. This data is then transformed into a readable form.
2. If the first one fails, this function tries to open a stream connection and reads the banner got from this connection.
3. This banner is then tested for know patterns for different services

These services can be currently detected:

| Service name               | Result is generated | Banner is saved   | Additional Information                                            |
| -------------------------- | ------------------- | ----------------- | ----------------------------------------------------------------- |
| chargen                    | Yes                 | No                |                                                                   |
| echo                       | Yes                 | No                |                                                                   |
| http-rpc-epmap             | Yes                 | Yes               |                                                                   |
| ncacn_http                 | Yes                 | Yes               |                                                                   |
| vnc                        | Yes                 | Yes               |                                                                   |
| nntp                       | Yes                 | Yes               |                                                                   |
| swat                       | No                  | No                |                                                                   |
| vqServer-admin             | No                  | No                |                                                                   |
| mldonkey                   | Yes                 | No                |                                                                   |
| www                        | Yes                 | Yes               | http server                                                       |
| AdSubtract                 | Yes                 | Yes               |                                                                   |
| gopher                     | Yes                 | No                |                                                                   |
| realserver                 | Yes                 | Yes               |                                                                   |
| smtp                       | Yes                 | Yes               | If banner contains ` postfix`, the key `smtp/postfix` is set to 1 |
| snpp                       | Yes                 | Yes               |                                                                   |
| ftp                        | Yes                 | Yes, if available |                                                                   |
| ssh                        | Yes                 | No                |                                                                   |
| http_proxy                 | Yes                 | No                |                                                                   |
| pop1                       | No                  | Yes               |                                                                   |
| pop2                       | Yes                 | Yes               |                                                                   |
| pop3                       | Yes                 | Yes               |                                                                   |
| imap                       | Yes                 | Yes               |                                                                   |
| auth                       | Yes                 | No                |                                                                   |
| postgresql                 | Yes                 | No                |                                                                   |
| sphinxql                   | Yes                 | No                |                                                                   |
| mysql                      | Yes                 | No                |                                                                   |
| cvspserver                 | Yes                 | No                |                                                                   |
| cvsup                      | Yes                 | No                |                                                                   |
| cvslockserver              | Yes                 | No                |                                                                   |
| rsync                      | Yes                 | No                |                                                                   |
| wild_shell                 | Yes (Vulnerability) | No                |                                                                   |
| telnet                     | Yes                 | No                |                                                                   |
| gnome14                    | Yes                 | No                |                                                                   |
| eggdrop                    | Yes                 | No                |                                                                   |
| netbus                     | Yes (Vulnerability) | No                |                                                                   |
| linuxconf                  | Yes                 | Yes               |                                                                   |
| finger                     | Yes                 | No                |                                                                   |
| vtun                       | Yes                 | Yes               |                                                                   |
| uucp                       | Yes                 | Yes               |                                                                   |
| lpd                        | Yes                 | No                |                                                                   |
| lyskom                     | Yes                 | No                |                                                                   |
| ph                         | Yes                 | No                |                                                                   |
| time                       | Yes                 | No                |                                                                   |
| iPlanetENS                 | Yes                 | No                |                                                                   |
| citrix                     | Yes                 | No                |                                                                   |
| giop                       | Yes                 | No                |                                                                   |
| exchg-routing              | Yes                 | Yes               |                                                                   |
| tcpmux                     | Yes                 | No                |                                                                   |
| BitTorrent                 | Yes                 | No                |                                                                   |
| smux                       | Yes                 | No                |                                                                   |
| LISa                       | Yes                 | No                |                                                                   |
| msdtc                      | Yes                 | Yes               |                                                                   |
| pop3pw                     | Yes                 | Yes               |                                                                   |
| whois++                    | Yes                 | Yes               |                                                                   |
| mon                        | Yes                 | Yes               |                                                                   |
| cpfw1                      | Yes                 | Yes (kinda??)     |                                                                   |
| psybnc                     | Yes                 | Yes (kinda??)     |                                                                   |
| shoutcast                  | Yes                 | Yes (kinda??)     |                                                                   |
| adsgone                    | Yes                 | Yes (kinda??)     |                                                                   |
| acap                       | Yes                 | Yes               |                                                                   |
| nagiosd                    | Yes                 | No                |                                                                   |
| teamspeak2                 | Yes                 | No                |                                                                   |
| websm                      | Yes                 | No                |                                                                   |
| ofa_express                | Yes                 | No                |                                                                   |
| smppd                      | Yes                 | No                |                                                                   |
| upsmon                     | Yes                 | No                |                                                                   |
| sub7                       | Yes (Vulnerability) | No                |                                                                   |
| spamd                      | Yes                 | No                |                                                                   |
| quicktime-streaming-server | Yes                 | No                |                                                                   |
| dameware                   | Yes                 | No                |                                                                   |
| SG_ClientAuth              | Yes                 | No                |                                                                   |
| listserv                   | Yes                 | No                |                                                                   |
| FsSniffer                  | Yes (Vulnerability) | No                |                                                                   |
| RemoteNC                   | Yes                 | No                |                                                                   |
| wrapped                    | Yes                 | No                | the key `Known/tcp/[port]`is not set                              |
| unknown                    | Yes                 | No                | Unknown service was detected                                      |
| gnuserv                    | Yes                 | No                |                                                                   |
| issrealsecure              | Yes                 | No                |                                                                   |
| vmware_auth                | Yes                 | No                |                                                                   |
| interscan_viruswall        | Yes                 | No                |                                                                   |
| pppd                       | Yes                 | No                |                                                                   |
| zebra                      | Yes                 | Yes               |                                                                   |
| ircxpro_admin              | Yes                 | No                |                                                                   |
| gnocatan                   | Yes                 | No                |                                                                   |
| power-broker-master        | Yes                 | No                |                                                                   |
| dicts                      | Yes                 | No                |                                                                   |
| pNSClient                  | Yes                 | No                |                                                                   |
| VeritasNetBackup           | Yes                 | No                |                                                                   |
| power-broker-master        | Yes                 | No                | fn name *mark_pblocald_server*, service name duplicated           |
| jabber                     | Yes                 | No                |                                                                   |
| avotus_mm                  | Yes                 | No                |                                                                   |
| socks                      | Yes                 | No                | The actual service name also contains a number like socks2        |
| DirectConnectHub           | Yes                 | No                |                                                                   |
| mongodb                    | Yes                 | No                |                                                                   |

## RETURN VALUE

None
