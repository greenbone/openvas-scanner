# ereg_replace

## NAME

**ereg_replace** - searches and replaces all the occurrences of a pattern inside a string

## SYNOPSIS

*string* **ereg_replace**(string: *string*, pattern: *string*, replace: *string*, icase: *bool*, rnul: *bool*);

**ereg_replace** takes up to 5 named arguments.

## DESCRIPTION

This function takes a string, searches for a pattern and replace all occurrences. If the pattern did not match the original string is returned.

The named argument *string* is a *string* containing the string to be searched.

The named argument *pattern* is a *string* containing the pattern to search for.

The named argument *replace* is a *string* containing the replacement string. It may contain escape sequences like \1 to reference found sub-patterns. The index is the number of the opening parenthesis.

The optional named argument *icase* is a *bool* and is used as a flag to enable/disable case sensitivity. Its default value is FALSE. FALSE means case sensitive, TRUE means case insensitive.

The optional named argument *rnul* is a *bool* and is used as a flag to enable/disable escaping nul-characters. Its default value is TRUE. TRUE means nul-characters are escaped. This enables to match strings with a nul-character in it, as such normally are used to mark the end of a string.

## RETURN VALUE

The new string with the pattern replaced with *replace* as *string*.

## ERRORS

The parameters *string* or *pattern* are missing.

## NOTE 

If you want to eliminate what’s before or after a pattern, you’ll have to play with something like ^.* or .*$ and \1.