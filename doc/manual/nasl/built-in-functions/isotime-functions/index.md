# ISO time functions

## GENERAL

The ISO time is standardized form for representing time formats from the year 0 to 9999. This family of functions are able to generate and alter given times in such formats, as well as get information about the current time.

In most 32 bit systems a signed 32 bit integer value is used to represent the system time. Unfortunately this only enables the usage of time between 1. January 1970 00:00:00 to 19. January 2038 03:14:07. However for VTs we sometimes need to calculate dates in the future beyond that. For example some certificates are (for whatever reason) valid for 30 years. To solve this problem in a platform independent way, we provide the time as a string and provide functions to work with them.

## TABLE OF CONTENT

- **[isotime_add](isotime_add.md)** - add years, days or seconds to an ISO time string
- **[isotime_is_valid](isotime_is_valid.md)** - check if a ISO time string is valid
- **[isotime_now](isotime_now.md)** - get the current time in the standard ISO format
- **[isotime_print](isotime_print.md)** - convert ISO time string to a better readable form
- **[isotime_scan](isotime_scan.md)** - convert a string into an ISO time string
