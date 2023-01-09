# eregmatch

## NAME

**eregmatch** - search for an pattern within a string

## SYNOPSIS

*array* **eregmatch**(string: *string*, pattern: *string*, icase: *bool*, rnul: *bool*, find_all: *bool*);

**eregmatch** takes up to 5 named arguments.

## DESCRIPTION

This function searches for a given pattern in a string. It additionally splits a found match into groups given with the regular expression with parentheses *()*. An array is returned. The first value in the array is always the whole pattern.

The named argument *string* is a *string* containing the string to be searched.

The named argument *pattern* is a *string* containing the pattern to search for.

The optional named argument *icase* is a *bool* and is used as a flag to enable/disable case sensitivity. Its default value is FALSE. FALSE means case sensitive, TRUE means case insensitive.

The optional named argument *rnul* is a *bool* and is used as a flag to enable/disable escaping nul-characters. Its default value is TRUE. TRUE means nul-characters are escaped. This enables to match strings with a nul-character in it, as such normally are used to mark the end of a string.

The named argument *find_all* is a *bool* and is used as a flag to enable/disable multiple matches. Its default value is FALSE. FALSE means the pattern matching stops after the first matching string. TRUE enables matching multiple patterns within the string. All matches, including the grouping is still returned within a single array.

## RETURN VALUE

An *array* with the matching string and its groups or *NULL* on error.

## ERRORS

One of the arguments *string* or *pattern* are missing.

Unable to compile *pattern*.

Error during pattern matching.

## EXAMPLES

Match a string with *find_all* disabled and enabled:
```c#
a = "abbc abbc";

b = eregmatch(string: a, pattern: "a(b)(b)c");

display(b);
# Displays [ 0: 'abbc', 1: 'b', 2: 'b' ]

b = eregmatch(string: a, pattern: "a(b)(b)c", find_all: TRUE);

display(b);
# Displays [ 0: 'abbc', 1: 'b', 2: 'b', 3: 'abbc', 4: 'b', 5: 'b' ]
```
