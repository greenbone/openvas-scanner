# get_host_open_port

## NAME

**get_host_open_port** - get an open TCP port on the target host

## SYNOPSIS

*any* **get_host_open_port**();

**get_host_open_port** takes no arguments.

## DESCRIPTION

This function is used by tests that need to speak to the TCP/IP stack but not to a specific service. 
Don't always return the first open port, otherwise it might get bitten by OSes doing active SYN flood countermeasures. Also, avoid returning 80 and 21 as open ports, as many transparent proxies are acting for these.

## RETURN VALUE

Return a random open port from a list (if there is many open ports), the port 21 or the port 80 are the last choices. Returns 0 if there is no open port.
