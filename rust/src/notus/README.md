# Notus Scanner

This is the rust library implementation of the Notus Scanner originating from https://github.com/greenbone/notus-scanner

Notus Scanner detects vulnerable products in a system environment. The scanning 
method is to evaluate internal system information. It does this very fast and
even detects currently inactive products because it does not need to interact
with each of the products.

To report about vulnerabilities, Notus Scanner receives collected system
information on the one hand and accesses the vulnerability information from the
notus feed on the other. Both input elements are in table form: the system
information is specific to each environment and the vulnerability information is
specific to each system type.

Notus Scanner integrates into the Greenbone Vulnerability Management framework
which allows to let it scan entire networks within a single task. Any
vulnerability test in the format of `.notus` files inside the Greenbone Feed
will be considered and automatically matched with the scanned environments.

A system environment can be the operating system of a host. But it could also be
containers like Docker or virtual machines. Neither of these need to be actively
running for scanning.

The Notus Scanner is implemented as a Rust library and published under an Open Source
license. Greenbone Networks maintains and extends it since it is embedded in the
Greenbone Professional Edition as well as in the Greenbone Cloud Services.

Greenbone also keeps the vulnerability information up-to-date via the feed on a
daily basis. The `.notus` format specification is open and part of the
documentation. To get the required notus files use the greenbone feed sync
https://github.com/greenbone/greenbone-feed-sync
