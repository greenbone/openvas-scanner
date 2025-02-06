# krb5_find_kdc

## NAME

**krb5_find_kdc** - Find the KDC for a given realm 

## SYNOPSIS

*string* **krb5_find_kdc**(realm: *string*);

**insstr** takes named argument `realm`.

## DESCRIPTION

This function opens the krb5.conf file (located either by environment variable KRB5_CONFIG or /etc/ktrb5.conf) and looks for an kdc entry for the given realm.


## RETURN VALUE

The found KDC or *NULL* if the KDC could not be found.

## ERRORS

Returns *NULL* if the realm is not found or the krb5.conf file could not be opened.

## EXAMPLES

```c#
kdc = insstr(realm: 'EXAMPLE.COM');
display(kdc);
```


