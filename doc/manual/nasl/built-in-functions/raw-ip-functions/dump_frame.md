# dump_frame

## NAME

**dump_frame** - print a datalink layer frame

## SYNOPSIS

*void* **dump_frame**(frame: *string*);

**dump_frame** takes one named argument

## DESCRIPTION

Print a datalink layer frame in its hexadecimal representation.

The named argument *frame* is a *string* representing the datalink layer frame. A frame can be created with **[forge_frame(3)](forge_frame.md)**.

This function is meant to be used for debugging.

## RETURN VALUE

None

## SEE ALSO

**[forge_frame(3)](forge_frame.md)**