#include <krb5/krb5.h>
#ifndef OPENVAS_KRB5
#define OPENVAS_KRB5 1
#include <krb5.h>
// Enables or disables the cache implementation.
//
// When using the cached functions it will store each credential in a memory
// list and refresh a ticket when required or  reauthenticate depending on the
// requirements in the background.
#define OPENVAS_KRB5_CACHED 1

typedef enum
{
  O_KRB5_SUCCESS,
  // Is returned when the krb5.conf was not found
  O_KRB5_CONF_NOT_FOUND,
  O_KRB5_CONF_NOT_CREATED,
  O_KRB5_TMP_CONF_NOT_CREATED,
  O_KRB5_TMP_CONF_NOT_MOVED,
  O_KRB5_REALM_NOT_FOUND,
  O_KRB5_EXPECTED_NULL,
  O_KRB5_EXPECTED_NOT_NULL,
  O_KRB5_UNABLE_TO_WRITE,
  // can only happen when GFP_ATOMIC is set on the kernel.
  O_KRB5_NOMEM,

  // Is an transitive error code to indicate an error originating from the
  // underlying krb5 implementation. It must be last and can not check by equals
  // operation as each krb5 error return will be added with that number
  // representation,
  O_KRB5_ERROR,
} OKrb5ErrorCode;

typedef struct
{
  krb5_context ctx;
  krb5_principal me;
  krb5_creds creds;
} OKrb5Element;

typedef struct
{
  const char *config_path;
  const char *realm;
  const char *user;
  const char *password;
} OKrb5Credential;

typedef struct
{
  krb5_data data;
  krb5_auth_context auth_context;
} OKrb5Data;

// Finds the kdc defined for the given realm.
//
// It returns the found kdc into `kdc` when `kdc` is not NULL.
// If kdc is not NULL it requires that the value pointer is NULL otherwise an
// error code is returned.
OKrb5ErrorCode
o_krb5_find_kdc (const OKrb5Credential *creds, char **kdc);
// Adds realm with the given kdc into krb5.conf if the krc5.conf is not found it
// will create a new one
OKrb5ErrorCode
o_krb5_add_realm (const OKrb5Credential *creds, const char *kdc);

// Is used to get a ticket based on the given credentials.
//
// It will store the ticket into element, it requires that elemenet is not NULL
// but that the value of element is NULL. Otherwise an error code is returned.
OKrb5ErrorCode
o_krb5_authenticate (const OKrb5Credential credentials, OKrb5Element **element);

OKrb5ErrorCode
o_krb5_request (const OKrb5Element *element, const char *data,
                const size_t data_len, OKrb5Data **out);

OKrb5ErrorCode
o_krb5_free_data (const OKrb5Element *element, OKrb5Data *data);

void
o_krb5_free_element (OKrb5Element *element);

#if OPENVAS_KRB5_CACHED == 1

typedef struct
{
  OKrb5Credential credentials;
  OKrb5Element *element;
  OKrb5ErrorCode last_error_code;
  unsigned long id;
} OKrb5CacheElement;

typedef struct
{
  size_t cap;
  size_t len;
  OKrb5CacheElement **elements;
} OKrb5CacheList;

OKrb5ErrorCode
o_krb5_cache_init (void);
OKrb5ErrorCode
o_krb5_cache_clear (void);

OKrb5CacheElement *
o_krb5_cache_find (const OKrb5Credential *cred);
OKrb5ErrorCode
o_krb5_cache_authenticate (const OKrb5Credential credentials,
                           OKrb5CacheElement **out);

OKrb5ErrorCode
o_krb5_cache_request (const OKrb5Credential credentials, const char *data,
                      const size_t data_len, OKrb5Data **out);
#endif

#endif
