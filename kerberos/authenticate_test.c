#include "../misc/openvas-krb5.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUARD_ENV_SET(var, env)                  \
  do                                             \
    {                                            \
      var = okrb5_slice_from_str (getenv (env)); \
      if (var.len == 0)                          \
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
  OKrb5GSSContext *context = NULL;
  struct OKrb5Slice from_application = {.data = NULL, .len = 0};
  struct OKrb5Slice *to_application = NULL;
  bool more = false;
  GUARD_ENV_SET (credentials.config_path, "KRB5_CONFIG");
  GUARD_ENV_SET (credentials.realm, "KRB5_REALM");
  GUARD_ENV_SET (credentials.user.user, "KRB5_USER");
  GUARD_ENV_SET (credentials.user.password, "KRB5_PASSWORD");
  GUARD_ENV_SET (credentials.target.host_name, "KRB5_TARGET_HOST");
  GUARD_ENV_SET (credentials.kdc, "KRB5_KDC");
  credentials.target.service = okrb5_slice_from_str ("cifs");
  memset (&credentials.target.domain, 0, sizeof (struct OKrb5Slice));
  printf ("Using realm: %s\n", (char *) credentials.realm.data);
  // TODO: move to overall function
  // TODO: refactor signature to use slice
  // if (o_krb5_find_kdc (&credentials, &kdc))
  //   {
  //     if (o_krb5_add_realm (&credentials, credentials.kdc.data))
  //       {
  //         fprintf (stderr, "Unable to add kdc\n");
  //         return 1;
  //       }
  //   }
  // else
  //   {
  //     printf ("Using kdc: %s\n", kdc);
  //     free (kdc);
  //   }
  context = okrb5_gss_init_context ();
  printf ("Using realm: %s\n", (char *) credentials.realm.data);
  if ((result = o_krb5_gss_prepare_context (&credentials, context)))
    {
      fprintf (stderr, "Unable to prepare context: %d\n", result);
      return 1;
    }
  printf ("Using realm: %s\n", (char *) credentials.realm.data);
  // first call always empty
  if ((result = o_krb5_gss_update_context (context, &from_application,
                                           &to_application, &more)))
    {
      fprintf (stderr, "Unable to update context: %d\n", result);
      return 1;
    }
  printf ("success: %d: outdata_len: %zu\n", result, to_application->len);

  for (size_t i = 0; i < to_application->len; i++)
    {
      printf ("%02x", ((char *) to_application->data)[i]);
    }
  printf ("\n");
}
