# Redis Data Model for OpenVAS

- [Redis Data Model for OpenVAS](#redis-data-model-for-openvas)
  - [DB 0: In-Use List](#db-0-in-use-list)
  - [DB 1: NVTI Cache](#db-1-nvti-cache)
  - [DB 2 .. DB N: Temporary KB for tasks and single scanned host](#db-2--db-n-temporary-kb-for-tasks-and-single-scanned-host)
    - [Temporary KB for task](#temporary-kb-for-task)
    - [Temporary KB for a single host](#temporary-kb-for-a-single-host)
  - [Data Content Examples](#data-content-examples)
    - [Before starting a task](#before-starting-a-task)
    - [After loading the data to start a scan](#after-loading-the-data-to-start-a-scan)
    - [After starting OpenVAS, during One Scan With One Host](#after-starting-openvas-during-one-scan-with-one-host)
    - [During One Scan With Two Hosts](#during-one-scan-with-two-hosts)
    - [During Two Scans With Each One Hosts](#during-two-scans-with-each-one-hosts)
    - [During Two Scans With Each Two Hosts](#during-two-scans-with-each-two-hosts)

This document explains the current Redis structures as used by OpenVAS.

Please refer to [redis_config.md](./redis_config.md) on how to configure and
manage the redis service.

Having an empty Redis (flushed), when OpenVAS starts, two Redis DBs are
taken into use. These are DB 0 and DB 1, which are permanent stores and they
are never deleted or flushed by OpenVAS.

## DB 0: In-Use List

In DB 0 there is only one hash type entry called `GVM.__GlobalDBIndex`. In this
hash is stored a list of in-use DBs. As this is the initial DB, OpenVAS
never tries to take it for another purpose. Each time in which OpenVAS
needs to set a new KB, it will start to search from DB 1.

We can see this with the command line client redis-cli:

```
$ redis-cli -s /run/redis-openvas/redis.sock

redis /run/redis-openvas/redis.sock> SELECT 0
OK

redis /run/redis-openvas/redis.sock> KEYS *
1) "GVM.__GlobalDBIndex"

redis /run/redis-openvas/redis.sock> HGETALL GVM.__GlobalDBIndex
1) "1"
2) "1"
```

With the last command `HGETALL` we get the key-value tuples saved into the
hash. In this case we can see that there is a key named “1” (item 1) and the
value for this key is also “1” (item 2). All this means that the DB 1 is in
use. Another way to see the same is using the command
 `HGET GVM.__GlobalDBIndex 1` to check directly if there is a key named “1” in
the hash. If the key exist, we will get the value stored there.

```
redis /run/redis-openvas/redis.sock> HGET GVM.__GlobalDBIndex 1
"1"

redis /run/redis-openvas/redis.sock> HGET GVM.__GlobalDBIndex 2
(nil)
```

As can be seen, there is no key 2 set.

## DB 1: NVTI Cache

In DB 1 is stored the NVT’s metadata (what before was in .nvti files) and
other information such as NVT’s timestamps and Checksums, for signature
verification.

```
redis /run/redis-openvas/redis.sock[3]> SELECT 1
OK

redis /run/redis-openvas/redis.sock[1]> KEYS *
     1) "nvt:1.3.6.1.4.1.25623.1.0.901173"
     2) "nvt:1.3.6.1.4.1.25623.1.0.120201"
     3) "filename:2017/gb_ubuntu_USN_3384_2.nasl:oid"
     4) "filename:pre2008/roxen_counter.nasl:timestamp"
     5) "filename:2015/ELSA-2011-0328.nasl:timestamp"
     …
```

Each *nvt:OID* entry is a list which stores the NVT’s metadata, while the
other ones are set types.

## DB 2 .. DB N: Temporary KB for tasks and single scanned host

To run a task, OpenVAS needs some data, like the target (single hosts, multiple
hosts, a network) and the port list, a list of plugins to be launched and other
necessary data to perform the scan. When OpenVAS is started, it gets an scan-id
as command parameter.

```
openvas --scan-start=<scan-id>
```

### Temporary KB for task

When OpenVAS is started, it takes all the necessary data from a KB. This KB is
filled by OSPD-OpenVAS, and OpenVAS found this KB because it has a key with
the scan-id. This is the way in which an OpenVAS process found the KB to perform
its task.
Each single task has each own main kb with the data necessary for running the scan
and this KB is released once the complete scan ended. This means, when all
single hosts in the target were scanned, the main kb data will be deleted
and the in-use DB list inside the hash `GVM.__GlobalDBIndex` is updated.

The task main KB is used for storing the results. Each result produced by NVTs
as well as the the progress status of the currently scanned hosts will be stored
in this KB.

### Temporary KB for a single host
Each host to be scanned takes a new DB for the KB. The host KB is used to
store some scan preferences and results for this specific host. When the host
scan finished, the KB and thus the DB is deleted with all its content and
freed. Then, the in-use DB list inside the hash `GVM.__GlobalDBIndex` is
updated.

## Data Content Examples

### Before starting a task

```
DB 0 -> 1) "GVM.__GlobalDBIndex" -> "1" "1"

DB 1 -> 1) "filename:2016/gb_fedora_2016_d957ffbac1_webkitgtk4_fc23.nasl:oid"
        2) "filename:2013/gb_fedora_2013_19285_java-1.7.0-openjdk_fc18.nasl:timestamp"
        3) "nvt:1.3.6.1.4.1.25623.1.0.882624"
        4) "nvt:1.3.6.1.4.1.25623.1.0.901039"
        5) "nvt:1.3.6.1.4.1.25623.1.0.863661"
        .
        .
        .
        134997) "nvt:1.3.6.1.4.1.25623.1.0.10613"
        134998) "filename:2017/gb_imagemagick_info_disc_n_sec_bypass_vuln_macosx.nasl:oid"
        134999) "filename:2017/gb_fedora_2017_cf1944f480_libpng15_fc25.nasl:oid"
        135000) "filename:2015/gb_junos_cve-2014-6386.nasl:timestamp

DB 2 -> (empty list or set)
```

### After loading the data to start a scan
In DB 2 can be seen some internal/* keys. While almost all keys are used for
internal communication between OpenVAS and OSPD-OpenVAS, only
'internal/<scan-id>/scanprefs' has the data necessary to run the scan.

```
DB 0 -> 1) "GVM.__GlobalDBIndex" -> "1" "1"
                                 -> "2" "1"

DB 1 -> 1) "filename:2016/gb_fedora_2016_d957ffbac1_webkitgtk4_fc23.nasl:oid"
        2) "filename:2013/gb_fedora_2013_19285_java-1.7.0-openjdk_fc18.nasl:timestamp"
        3) "nvt:1.3.6.1.4.1.25623.1.0.882624"
        4) "nvt:1.3.6.1.4.1.25623.1.0.901039"
        5) "nvt:1.3.6.1.4.1.25623.1.0.863661"
        .
        .
        .
        134997) "nvt:1.3.6.1.4.1.25623.1.0.10613"
        134998) "filename:2017/gb_imagemagick_info_disc_n_sec_bypass_vuln_macosx.nasl:oid"
        134999) "filename:2017/gb_fedora_2017_cf1944f480_libpng15_fc25.nasl:oid"
        135000) "filename:2015/gb_junos_cve-2014-6386.nasl:timestamp

DB 2 -> 1) "internal/dbindex"
        2) "internal/ovas_pid"
        3) "internal/acc04534-54b4-4137-a78a-c3d4441ede37"
        4) "internal/scanid"
        5) "internal/acc04534-54b4-4137-a78a-c3d4441ede37/scanprefs"
        6) "internal/dd91d963-d71f-4c98-bc18-c6fae29633aa/globalscanid"
```
### After starting OpenVAS, during One Scan With One Host

```
DB 0 -> 1) "GVM.__GlobalDBIndex" -> "1" "1"
                                 -> "2" "1"
                                 -> "3" "1"

DB 1 -> 1) "filename:2016/gb_fedora_2016_d957ffbac1_webkitgtk4_fc23.nasl:oid"
        2) "filename:2013/gb_fedora_2013_19285_java-1.7.0-openjdk_fc18.nasl:timestamp"
        3) "nvt:1.3.6.1.4.1.25623.1.0.882624"
        4) "nvt:1.3.6.1.4.1.25623.1.0.901039"
        5) "nvt:1.3.6.1.4.1.25623.1.0.863661"
        .
        .
        .
        134997) "nvt:1.3.6.1.4.1.25623.1.0.10613"
        134998) "filename:2017/gb_imagemagick_info_disc_n_sec_bypass_vuln_macosx.nasl:oid"
        134999) "filename:2017/gb_fedora_2017_cf1944f480_libpng15_fc25.nasl:oid"
        135000) "filename:2015/gb_junos_cve-2014-6386.nasl:timestamp

DB 2 -> 1) "internal/dbindex"
        2) "internal/ovas_pid"
        3) "internal/acc04534-54b4-4137-a78a-c3d4441ede37"
        4) "internal/scanid"
        5) "internal/dd91d963-d71f-4c98-bc18-c6fae29633aa/globalscanid"
        6) "internal/status"
        7) "internal/results

DB 3 -> 1) "Services/irc"
        2) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        3) "internal/ip"
        .
        .
        .
        1975) "Services/irc"
        1976) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        1977) "Cache/80/URL_/mutillidae/documentation/wiki/index.php"
        1978) "SMB/name"
        1979) "Cache/80/URL_/us/"
        1980) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.10718/EXIT_CODE"
        1981) "Services/vnc"
        1982) "www/80/content/cgis//twiki/bin/edit/TWiki/TWikiSiteTools"
        1983) "Cache/80/URL_/sys/"
```

### During One Scan With Two Hosts

```
DB 0 -> 1) "GVM.__GlobalDBIndex" -> "1" "1"
                                 -> "2" "1"
                                 -> "3" "1"
                                 -> "4" "1"

DB 1 -> 1) "filename:2016/gb_fedora_2016_d957ffbac1_webkitgtk4_fc23.nasl:oid"
        2) "filename:2013/gb_fedora_2013_19285_java-1.7.0-openjdk_fc18.nasl:timestamp"
        3) "nvt:1.3.6.1.4.1.25623.1.0.882624"
        4) "nvt:1.3.6.1.4.1.25623.1.0.901039"
        5) "nvt:1.3.6.1.4.1.25623.1.0.863661"
        .
        .
        .
        134997) "nvt:1.3.6.1.4.1.25623.1.0.10613"
        134998) "filename:2017/gb_imagemagick_info_disc_n_sec_bypass_vuln_macosx.nasl:oid"
        134999) "filename:2017/gb_fedora_2017_cf1944f480_libpng15_fc25.nasl:oid"
        135000) "filename:2015/gb_junos_cve-2014-6386.nasl:timestamp

DB 2 -> 1) "internal/dbindex"
        2) "internal/ovas_pid"
        3) "internal/acc04534-54b4-4137-a78a-c3d4441ede37"
        4) "internal/scanid"
        5) "internal/dd91d963-d71f-4c98-bc18-c6fae29633aa/globalscanid"
        6) "internal/status"
        7) "internal/results


DB 3 -> 1) "Services/irc"
        2) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        3) "internal/ip"
        .
        .
        .
        1975) "Services/irc"
        1976) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        1977) "Cache/80/URL_/mutillidae/documentation/wiki/index.php"
        1978) "SMB/name"
        1979) "Cache/80/URL_/us/"
        1980) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.10718/EXIT_CODE"
        1981) "Services/vnc"
        1982) "www/80/content/cgis//twiki/bin/edit/TWiki/TWikiSiteTools"
        1983) "Cache/80/URL_/sys/"

DB 4 -> 1) "Cache/80/URL_/doc/scripts.php"
        2) "Cache/80/URL_/twiki/pub/TWiki/TWikiPreferences/scripts.php"
        3) "Cache/80/URL_/loader/"
        4) "Cache/80/URL_/CVS/"
        .
        .
        .
        1453) "internal/ip"
        1454) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.111068/OS"
        1458) "Cache/80/URL_/test/testoutput/readme.txt"
        1459) "Cache/80/URL_/cgilib/"
```

### During Two Scans With Each One Hosts

```
DB 0 -> 1) "GVM.__GlobalDBIndex" -> "1" "1"
                                 -> "2" "1"
                                 -> "3" "1"
                                 -> "4" "1"
                                 -> "5" "1"

DB 1 -> 1) "filename:2016/gb_fedora_2016_d957ffbac1_webkitgtk4_fc23.nasl:oid"
        2) "filename:2013/gb_fedora_2013_19285_java-1.7.0-openjdk_fc18.nasl:timestamp"
        3) "nvt:1.3.6.1.4.1.25623.1.0.882624"
        4) "nvt:1.3.6.1.4.1.25623.1.0.901039"
        5) "nvt:1.3.6.1.4.1.25623.1.0.863661"
        .
        .
        .
        134997) "nvt:1.3.6.1.4.1.25623.1.0.10613"
        134998) "filename:2017/gb_imagemagick_info_disc_n_sec_bypass_vuln_macosx.nasl:oid"
        134999) "filename:2017/gb_fedora_2017_cf1944f480_libpng15_fc25.nasl:oid"
        135000) "filename:2015/gb_junos_cve-2014-6386.nasl:timestamp

DB 2 -> 1) "internal/dbindex"
        2) "internal/ovas_pid"
        3) "internal/acc04534-54b4-4137-a78a-c3d4441ede37"
        4) "internal/scanid"
        5) "internal/dd91d963-d71f-4c98-bc18-c6fae29633aa/globalscanid"
        6) "internal/status"
        7) "internal/results

DB 3 -> 1) "Services/irc"
        2) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        3) "internal/ip"
        .
        .
        .
        1975) "Services/irc"
        1976) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        1977) "Cache/80/URL_/mutillidae/documentation/wiki/index.php"
        1978) "SMB/name"
        1979) "Cache/80/URL_/us/"
        1980) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.10718/EXIT_CODE"
        1981) "Services/vnc"
        1982) "www/80/content/cgis//twiki/bin/edit/TWiki/TWikiSiteTools"
        1983) "Cache/80/URL_/sys/"

DB 4 -> 1) "internal/dbindex"
        2) "internal/ovas_pid"
        3) "internal/da234534-54b4-4137-a78a-c3d4441edd42"
        4) "internal/scanid"
        5) "internal/91a1d963-d71f-4c98-bc18-c6fae296acd1/globalscanid"
        6) "internal/status"
        7) "internal/results


DB 5 -> 1) "Cache/80/URL_/doc/scripts.php"
        2) "Cache/80/URL_/twiki/pub/TWiki/TWikiPreferences/scripts.php"
        3) "Cache/80/URL_/loader/"
        4) "Cache/80/URL_/CVS/"
        .
        .
        .
        1453) "internal/ip"
        1454) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.111068/OS"
        1458) "Cache/80/URL_/test/testoutput/readme.txt"
        1459) "Cache/80/URL_/cgilib/"
```

### During Two Scans With Each Two Hosts

```
DB 0 -> 1) "GVM.__GlobalDBIndex" -> "1" "1"
                                 -> "2" "1"
                                 -> "3" "1"
                                 -> "4" "1"
                                 -> "5" "1"
                                 -> "6" "1"
                                 -> "7" "1"

DB 1 -> 1) "filename:2016/gb_fedora_2016_d957ffbac1_webkitgtk4_fc23.nasl:oid"
        2) "filename:2013/gb_fedora_2013_19285_java-1.7.0-openjdk_fc18.nasl:timestamp"
        3) "nvt:1.3.6.1.4.1.25623.1.0.882624"
        4) "nvt:1.3.6.1.4.1.25623.1.0.901039"
        5) "nvt:1.3.6.1.4.1.25623.1.0.863661"
        .
        .
        .
        134997) "nvt:1.3.6.1.4.1.25623.1.0.10613"
        134998) "filename:2017/gb_imagemagick_info_disc_n_sec_bypass_vuln_macosx.nasl:oid"
        134999) "filename:2017/gb_fedora_2017_cf1944f480_libpng15_fc25.nasl:oid"
        135000) "filename:2015/gb_junos_cve-2014-6386.nasl:timestamp

DB 2 -> 1) "internal/dbindex"
        2) "internal/ovas_pid"
        3) "internal/acc04534-54b4-4137-a78a-c3d4441ede37"
        4) "internal/scanid"
        5) "internal/dd91d963-d71f-4c98-bc18-c6fae29633aa/globalscanid"
        6) "internal/status"
        7) "internal/results

DB 3 -> 1) "Services/irc"
        2) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        3) "internal/ip"
        .
        .
        .
        1975) "Services/irc"
        1976) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        1977) "Cache/80/URL_/mutillidae/documentation/wiki/index.php"
        1978) "SMB/name"
        1979) "Cache/80/URL_/us/"
        1980) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.10718/EXIT_CODE"
        1981) "Services/vnc"
        1982) "www/80/content/cgis//twiki/bin/edit/TWiki/TWikiSiteTools"
        1983) "Cache/80/URL_/sys/"

DB 4 -> 1) "Cache/80/URL_/doc/scripts.php"
        2) "Cache/80/URL_/twiki/pub/TWiki/TWikiPreferences/scripts.php"
        3) "Cache/80/URL_/loader/"
        4) "Cache/80/URL_/CVS/"
        .
        .
        .
        1453) "internal/ip"
        1454) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.111068/OS"
        1458) "Cache/80/URL_/test/testoutput/readme.txt"
        1459) "Cache/80/URL_/cgilib/"

DB 5 -> 1) "internal/dbindex"
        2) "internal/ovas_pid"
        3) "internal/da234534-54b4-4137-a78a-c3d4441edd42"
        4) "internal/scanid"
        5) "internal/91a1d963-d71f-4c98-bc18-c6fae296acd1/globalscanid"
        6) "internal/status"
        7) "internal/results

DB 6 -> 1) "Services/irc"
        2) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        3) "internal/ip"
        .
        .
        .
        1975) "Services/irc"
        1976) "www/80/content/cgis//twiki/bin/rdiff/TWiki/TWikiSiteTools"
        1977) "Cache/80/URL_/mutillidae/documentation/wiki/index.php"
        1978) "SMB/name"
        1979) "Cache/80/URL_/us/"
        1980) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.10718/EXIT_CODE"
        1981) "Services/vnc"
        1982) "www/80/content/cgis//twiki/bin/edit/TWiki/TWikiSiteTools"
        1983) "Cache/80/URL_/sys/"

DB 7 -> 1) "Cache/80/URL_/doc/scripts.php"
        2) "Cache/80/URL_/twiki/pub/TWiki/TWikiPreferences/scripts.php"
        3) "Cache/80/URL_/loader/"
        4) "Cache/80/URL_/CVS/"
        .
        .
        .
        1453) "internal/ip"
        1454) "HostDetails/NVT/1.3.6.1.4.1.25623.1.0.111068/OS"
        1458) "Cache/80/URL_/test/testoutput/readme.txt"
        1459) "Cache/80/URL_/cgilib/"
```
