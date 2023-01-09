# egrep

## NAME

**egrep** - looks for a patter in a string line by line and concatenates all lines the string was found

## SYNOPSIS

*string* **egrep**(string: *string*, pattern: *string*, icase: *bool*, rnul: *bool*);

*string* **ereg_replace**(string: *string*, pattern: *string*, replace: *string*, icase: *bool*, rnul: *bool*);

## DESCRIPTION

This function takes a string and searches for a pattern in it line by line. Each line, which had a match is then concatenate and returned.

The named argument *string* is a *string* containing the string to be searched.

The named argument *pattern* is a *string* containing the pattern to search for.

The optional named argument *icase* is a *bool* and is used as a flag to enable/disable case sensitivity. Its default value is FALSE. FALSE means case sensitive, TRUE means case insensitive.

The optional named argument *rnul* is a *bool* and is used as a flag to enable/disable escaping nul-characters. Its default value is TRUE. TRUE means nul-characters are escaped. This enables to match strings with a nul-character in it, as such normally are used to mark the end of a string.

## RETURN VALUE

The concatenated lines, in which the patter was found as *string* or *NULL* on error.

## ERRORS

One of the arguments *string* or *pattern* are missing.

Unable to compile pattern.
