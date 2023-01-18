# islocalhost

## NAME

**islocalhost** - Check if the  target host is the same as the attacking host

## SYNOPSIS

*any* **islocalhost**();

**islocalhost** takes no arguments

## DESCRIPTION

Check if the  target host is the same as the attacking host
This tests is performed via a packet sent to IP and checking if it is LIKELY to be routed through the kernel localhost interface.

## RETURN VALUE

Return True or False.
