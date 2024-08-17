#include "openvas-krb5.h"

#include <krb5/krb5.h>
#include <stdio.h>
#include <stdlib.h>

#define REALM "GBKERB.LOCAL"

#define GUARD_ENV_SET(var, env)                  \
  do                                             \
    {                                            \
      if ((var = getenv (env)) == NULL)          \
        {                                        \
          fprintf (stderr, env " is not set\n"); \
          return 1;                              \
        }                                        \
    }                                            \
  while (0)
int
main ()
{
  char *kdc = NULL;
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  OKrb5Credential credentials;
  OKrb5Element *element = NULL;
  OKrb5Data *data = NULL;
  GUARD_ENV_SET (credentials.config_path, "KRB5_CONFIG");
  GUARD_ENV_SET (credentials.realm, "KRB5_REALM");
  GUARD_ENV_SET (credentials.user, "KRB5_USER");
  GUARD_ENV_SET (credentials.password, "KRB5_PASSWORD");

  if (o_krb5_find_kdc (&credentials, &kdc))
    {
      GUARD_ENV_SET (kdc, "KRB5_KDC");
      if (o_krb5_add_realm (&credentials, kdc))
        {
          fprintf (stderr, "Unable to add kdc\n");
          return 1;
        }
    }
  else
    {
      printf ("Using kdc: %s\n", kdc);
      free (kdc);
    }
  if ((result = o_krb5_authenticate (credentials, &element)))
    {
      fprintf (stderr, "Error: %d: %s\n", result,
               krb5_get_error_message (element->ctx, result - O_KRB5_ERROR));
      return result;
    }

  printf ("Authentication Token:\n");
  printf ("--------------------\n");
  printf ("End time:     %d\n", element->creds.times.endtime);
  printf ("start time:     %d\n", element->creds.times.starttime);
  printf ("Renew till:     %d\n", element->creds.times.renew_till);
  if ((result = o_krb5_request (element, "test", 5, &data)))
    {
      fprintf (stderr, "unable to create request: %d", result);
    }
  if ((result = o_krb5_free_data (element, data)))
    {
      fprintf (stderr, "unable to free request: %d", result);
    }

  return 0;
}
