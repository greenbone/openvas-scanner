# greenbone-nvt-sync

## NAME

greenbone-nvt-sync - updates the OpenVAS NVTs from Greenbone Security
Feed or Community Feed

## SYNOPSIS

**greenbone-nvt-sync**

## DESCRIPTION

The **OpenVAS Scanner** performs several security checks. These are
called Network Vulnerability Tests (NVTs) and are implemented in the
programming language NASL. Some NVTs are wrappers for external tools. As
new vulnerabilities are published every day, new NVTs appear in the
Greenbone Security Feed. This feed is commercial and requires a
respective subscription key. In case no subscription key is present, the
update synchronisation will use the Community Feed instead.

\
The script **greenbone-nvt-sync** will fetch all new and updated
security checks and install them at the proper location. Once this is
done OpenVAS Scanner, openvas(1) will automatically detect that new and
updated NVTs are present and consider them for next activities.

## SEE ALSO

**[openvas(1)](openvas/openvas.md)**

## AUTHOR

This manual page was written by Jan-Oliver Wagner
\<jan-oliver.wagner@greenbone.net\>.

The **greenbone-nvt-sync** script was written by Greenbone Networks
GmbH.
