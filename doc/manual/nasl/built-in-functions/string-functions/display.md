# display

## NAME

**display** - display any number of NASL values

## SYNOPSIS

*int* **display**(*any*...);

**display** takes any number of arguments.

## DESCRIPTION

This function displays any number of NASL values. Internally it calls **[string(3)](string.md)** to concatenate them.

## RETURN VALUE

Size of the displayed string.
