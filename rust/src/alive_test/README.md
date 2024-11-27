# Alive Test 

This is the rust library implementation of Boreas from https://github.com/greenbone/gvm-libs/ and https://github.com/greenbone/boreas/

Alive Test is a library to scan for alive hosts as well as a command line tool integrated in scannerctl, which replaces the former Boreas library and command line tool written in C.

It supports IPv4 and IPv6 address ranges and allows to exclude certain addresses from a range. The alive ping tests support ICMP, TCP-ACK, TCP-SYN and ARP and any combination. For TCP ping an individual port list can be applied.
