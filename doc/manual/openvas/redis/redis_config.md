# Redis KB server

- [Redis KB server](#redis-kb-server)
  - [Presentation](#presentation)
  - [Connection](#connection)
  - [Database number](#database-number)
  - [Clients numbers](#clients-numbers)
  - [Volatile keys](#volatile-keys)
  - [Debugging and monitoring a scan via redis](#debugging-and-monitoring-a-scan-via-redis)

## Presentation

[Redis](http://redis.io) is used to store and access the KB (Knowledge Base).
Scans won't run if they cannot access the server and might be significantly
slowed down if redis is not properly configured.

The feature has been developed with neither cluster mode nor replication
enabled. Redis 3.2 and higher are supported.

## Connection

OpenVAS can currently only access redis via a unix socket. This choice has been
made for the sake of speed and security. No authentication is supported yet, we
rely on filesystem permissions to protect the KBs.

The path to the unix socket is `/run/redis-openvas/redis.sock` by default, and
can be changed using the `db_address` parameter.

On the redis side, use the following directives:

```
port 0 # prevent redis from listening on a TCP socket
unixsocket /run/redis-openvas/redis.sock
unixsocketperm 770
timeout 0
```

## Database number

Multiple KBs can be served in parallel, for multiple hosts scanned by one or
several tasks. This is done using redis databases, which are independent
namepaces. The DB#0, which is where every new connected client starts, is
reserved and used to schedule concurrent accesses to the available namespaces.
It contains a single variable, called `GVM.__GlobalDBIndex`. This variable
is a bitmap of the different namespaces. When opening a new DB, the scanner will
look for the first bit that is not set, starting from 1 to the maximum number of
available DBs. If none is found, the scanner will enter a wait and retry loop.
Otherwise, it will (atomically, along with the check) set the bit to 1 and
switch to the selected namespace.

It is therefore important that redis exports enough databases. This number can
be calculated using the following formula:

```
#DB = 1 + (#of parallel tasks) * (#of parallel hosts)
```

The desired/needed value should be set to redis.conf, as a `databases`
directive.

For instance:

```
databases 128
```

## Clients numbers

Redis can limit the number of clients served concurrently. This can be safely
set to a pretty high number. You can estimate the number of clients that the
server will have to serve:

```
#CLI = 1 + (#of parallel tasks) * (#of parallel hosts) * (#of concurrent NVTs)
```

For instance:

```
maxclients    512
```

## Volatile keys

An expire may be set by openvas for keys which may not be absolutely necessary.

A `maxmemory-policy` can be chosen in conjunction with `maxmemory`.
When the memory limit is reached Redis will try to remove keys according
to the eviction policy selected. Both options can be set via the redis.conf
file. See [the reference config](https://github.com/redis/redis/blob/5.0/redis.conf)
for further documentation of these options.

If no `maxmemory` and `maxmemory-policy` is chosen the redis memory may
increase until the OS runs out of memory.

Only downside of these options is that when `maxmemory` is reached and there
are no more keys to evict then no keys are added to redis anymore.
This is done without notice and may lead to missing or incomplete results.

## Debugging and monitoring a scan via redis

Once redis-server is started, you can issue the following command to see
everything that happens during the execution.

```sh
$ redis-cli -s <path to the redis server socket> MONITOR
```

The default path is `/run/redis-openvas/redis.sock`. Then start the scan or
openvas-nasl. You should be able to follow precisely the interactions
between the scanner and the KB server.

See also: http://redis.io/commands/MONITOR


To enter an interactive mode type

```
$ redis-cli -s <path to the redis server socket>

redis /run/redis-openvas/redis.sock> keys *
1) "OpenVAS.__GlobalDBIndex"

redis /run/redis-openvas/redis.sock> select 1
OK
```

Then you can search for keys with a pattern (*"keys *"* will dump all
keys present):

```
redis /run/redis-openvas/redis.sock[1]> keys "*ALARM*"
```

Note that keys will disappear once a scan of a host finished.
When the scanner is not active, the store is empty.

The keys contain sets, not strings. So instead of the `get` command
you need to use `smembers` to view the content:

```
redis /run/redis-openvas/redis.sock[1]> smembers Sun/VirtualBox/Lin/Ver
1) "4.3.12.93733"
```
