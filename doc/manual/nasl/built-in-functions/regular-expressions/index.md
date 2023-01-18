# Regular Expression Functions

## GENERAL

A regular expression is a sequence of characters that specifies a search pattern in text. Usually such patterns are used by string-searching algorithms for "find" or "find and replace" operations on strings, or for input validation.

Functions in this family will work with such regular expressions to find or replace specific patterns within a given string.

All the regex functions work the same way. If you want to match from the beginning / end of your string (or your line, in the case of egrep), you’ll have to use ^ or $. You should read your (POSIX) system manual for details on regular expressions.

## TABLE OF CONTENT

- **[egrep](egrep.md)** - looks for a patter in a string line by line and concatenates all lines the string was found
- **[eregmatch](eregmatch.md)** - search for an pattern within a string
- **[ereg](ereg.md)** - matches a given string against a regular expression
- **[ereg_replace](ereg_replace.md)** - searches and replaces all the occurrences of a pattern inside a string
