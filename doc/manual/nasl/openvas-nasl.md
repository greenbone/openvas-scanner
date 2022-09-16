# openvas-nasl

## NAME

openvas-nasl - NASL Attack Scripting Language

## SYNOPSIS

**openvas-nasl** *\<\[-Vh\] \[-T tracefile\] \[-s\] \[-t target\] \[-c
config_file\] \[-d\] \[-sX\] \> files\...*

## DESCRIPTION

**openvas-nasl** executes a set of NASL scripts against a given target
host. It can also be used to determine if a NASL script has any syntax
errors by running it in parse (**-p**) or lint (**-L**) mode.

## OPTIONS

**-T tracefile**

:   Makes nasl write verbosely what the script does in the file
    *tracefile* , ala \'set -x\' under sh

**-t target**

:   Apply the NASL script to *target* which may be a single host
    (127.0.0.1), a whole subnet (192.168.1.0/24) or several subnets
    (192.168.1.0/24, 192.168.243.0/24)

**-e iface**

:   Specifies the network interface to be used as the source for
    established connections.

**-s**

:   Sets the return value of safe_checks() to 1. (See the OpenVAS
    Scanner documentation to know what the safe checks are) Implies -B.

**-D**

:   Only run the description part of the script.

**-B**

:   Runs in description mode before running the script.

**-L**

:   **Lint** the script (run extended checks).

**-X**

:   Run the script with disabled signature verification.

**-h**

:   Show help

**-V**

:   Show the version of NASL.

**-d**

:   Output debug information to stderr.

**-r port-range**

:   This is the default range of ports that the scanner plugins will
    probe. The syntax of this option is flexible, it can be a single
    range (\"1-1500\"), several ports (\"21,23,80\"), several ranges of
    ports (\"1-1500,32000-33000\"). Note that you can specify UDP and
    TCP ports by prefixing each range by T or U. For instance, the
    following range will make openvas scan UDP ports 1 to 1024 and TCP
    ports 1 to 65535 : \"T:1-65535,U:1-1024\".

**-k key=value**

:   Set KB key to value. Can be used multiple times.

## SEE ALSO

**[openvas(1)](../openvas/openvas.md)**, **[openvas-nasl-lint(1)](openvas-nasl-lint.md)**

## HISTORY

NASL comes from a private project called \'pkt_forge\', which was
written in late 1998 by Renaud Deraison and which was an interactive
shell to forge and send raw IP packets (this pre-dates Perl\'s
Net::RawIP by a couple of weeks). It was then extended to do a wide
range of network-related operations and integrated into the scanner as
\'NASL\'.

The parser was completely hand-written and a pain to work with. In
Mid-2002, Michel Arboi wrote a bison parser for NASL, and he and Renaud
Deraison re-wrote NASL from scratch. Although the \"new\" NASL was
nearly working as early as August 2002, Michel\'s laziness made us wait
for early 2003 to have it working completely.

After the original authors decided to stop the Open Source development
in 2005, most changes and maintenance works were done by Greenbone
Networks.

## AUTHOR

Most of the engine is (C) 2003 Michel Arboi, most of the built-in
functions are (C) 2003 Renaud Deraison. Most new code since 2005
developed by Greenbone Networks GmbH.
