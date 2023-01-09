# match

## NAME

**match** - matches a string against a simple shell-like pattern

## SYNOPSIS

*bool* **match**(string: *string*, pattern: *string*, icase: *bool*);

**match** takes up to 3 named arguments.

## DESCRIPTION

This function matches a string against a simple shell-like pattern and returns *TRUE* or *FALSE*. This function is less powerful than **[ereg(3)](../regular-expressions/ereg.md** but it is quicker and its interface is simple.

The named argument *string* is a *string* containing the string to be searched.

The named argument *pattern* is a *string* containing the pattern to search for.

The optional named argument *icase* is a *bool* and is used as a flag to enable/disable case sensitivity. Its default value is *FALSE*. *FALSE* means case sensitive, *TRUE* means case insensitive.

## RETURN VALUE

*TRUE* if pattern matches, else *FALSE* or *NULL* on error.

## ERRORS

One of the named arguments *string* or *pattern* are missing.

## SEE ALSO

**[ereg(3)](../regular-expressions/ereg.md)**
