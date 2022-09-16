# Redis

## GENERAL

**Redis** is a in-memory data base with a simple key-value data structure. It belongs to the family of NoSQL databases and therefore is not relational. It is not suitable for complex data structures, but benefits from its speed.

## USAGE IN OPENVAS

The main use of Redis in OpenVAS is the communication. It is used to set information in order for OpenVAS to start a scan. This information are e.g. the host to scan, credentials for further access and configurations for the scanner. Additionally it is used for the scan internally to send information between forked processes, as each running NASL script is a forked process. The last usage is the reporting of information, errors and results.

## SEE ALSO

**redis-cli(1)**
