# ereg

## NAME

**ereg** - matches a given string against a regular expression

## SYNOPSIS

*bool* **ereg**(string: *string*, pattern: *string*, icase: *bool*, rnul: *bool*, multiline: *bool*);

**ereg** takes up to 5 named arguments.

## DESCRIPTION

This function takes a string and matches it against a regular expression.

The named argument *string* is a *string* containing the string to be searched.

The named argument *pattern* is a *string* containing the pattern to search for.

The optional named argument *icase* is a *bool* and is used as a flag to enable/disable case sensitivity. Its default value is FALSE. FALSE means case sensitive, TRUE means case insensitive.

The optional named argument *rnul* is a *bool* and is used as a flag to enable/disable escaping nul-characters. Its default value is TRUE. TRUE means nul-characters are escaped. This enables to match strings with a nul-character in it, as such normally are used to mark the end of a string.

The named argument *multiline* is a *bool* and is used as a flag to enable/disable multiline strings. Its default value is FALSE. FALSE means the string is truncated at the first appearance of a new line character. TRUE enables matching multiple lines.

## RETURN VALUE

TRUE, if the pattern matches, FALSE if not and *NULL* on error.

## ERRORS

One of the arguments *string* or *pattern* are missing.

Unable to compile pattern.
