# send_frame

## NAME

**send_frame** - send a frame to th  scanned host

## SYNOPSIS

*string* **send_frame**(frame: *string*, pcap_active: *bool*, pcap_filter: *string*, pcap_timeout: *int*);

**send_frame** takes 4 named arguments.

## DESCRIPTION

Send a frame to the currently scanned host with the option to listen to the answer.

The arguments are:
- frame: the frame to send, created with **[forge_frame(3)](forge_frame.md)**
- pcap_active: option to capture the answer, default is TRUE
- pcap_filter: filter for the answer
- pcap_timeout: time to wait for the answer in seconds, default 5

## RETURN VALUE

The answer of the send frame

## SEE ALSO

**[forge_frame(3)](forge_frame.md)**
