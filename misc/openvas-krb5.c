#include "openvas-krb5.h"

#include <assert.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GUARD_NULL(var, return_var)          \
  do                                         \
    {                                        \
      if (var != NULL)                       \
        {                                    \
          return_var = O_KRB5_EXPECTED_NULL; \
          goto result;                       \
        }                                    \
    }                                        \
  while (0)

#define GUARD_NOT_NULL(var, return_var)          \
  do                                             \
    {                                            \
      if (var == NULL)                           \
        {                                        \
          return_var = O_KRB5_EXPECTED_NOT_NULL; \
          goto result;                           \
        }                                        \
    }                                            \
  while (0)

#define ALLOCATE_AND_CHECK(var, type, n, return_var) \
  do                                                 \
    {                                                \
      var = (type *) calloc (n, sizeof (type));      \
      if (var == NULL)                               \
        {                                            \
          return_var = O_KRB5_NOMEM;                 \
          goto result;                               \
        }                                            \
    }                                                \
  while (0)

#define SKIP_WS(line, line_len, start, i)        \
  do                                             \
    {                                            \
      for (i = start; i < line_len; i++)         \
        {                                        \
          if (line[i] != ' ' && line[i] != '\t') \
            {                                    \
              break;                             \
            }                                    \
        }                                        \
    }                                            \
  while (0)

#define IS_STR_EQUAL(line, line_len, start, cmp, cmp_len) \
  ((line_len - start < cmp_len) ? 0                       \
   : (line_len == 0 && cmp_len == 0)                      \
     ? 1                                                  \
     : (memcmp (line + start, cmp, cmp_len) == 0))

#define MAX_LINE_LENGTH 1024
// Finds the kdc defined for the given realm.
OKrb5ErrorCode
o_krb5_find_kdc (const OKrb5Credential *creds, char **kdc)
{
  OKrb5ErrorCode result = O_KRB5_REALM_NOT_FOUND;
  char line[MAX_LINE_LENGTH];
  int state = 0;
  size_t last_element;
  size_t i, j;
  FILE *file;

  // we don't know if we should free it or just override it.
  // aborting instead.
  GUARD_NULL (*kdc, result);
  if ((file = fopen ((char *) &creds->config_path.data, "r")) == NULL)
    {
      result = O_KRB5_CONF_NOT_FOUND;
      goto result;
    }

  while (fgets (line, MAX_LINE_LENGTH, file))
    {
      line[strcspn (line, "\n")] = 0;
      last_element = strlen (line) - 1;
      SKIP_WS (line, last_element, 0, i);
      if (line[i] == '[' && line[last_element] == ']')
        {
          if (state != 0)
            {
              result = O_KRB5_REALM_NOT_FOUND;
              goto result;
            }
          if (IS_STR_EQUAL (line, last_element + 1, i, "[realms]", 8) == 1)
            {
              state = 1;
            }
        }
      else
        {
          if (line[i] == '}' || line[last_element] == '}')
            {
              state = 1;
            }
          else if (state == 1)
            {
              for (j = i; j <= last_element; j++)
                {
                  if (line[j] != ((char *) creds->realm.data)[j - i])
                    {
                      state = 2;
                      break;
                    }
                  if (j - i >= creds->realm.len)
                    {
                      break;
                    }
                }
              if (j - i == creds->realm.len)
                {
                  state = 3;
                }
            }
          else if (state == 3)
            {
              if (IS_STR_EQUAL (line, last_element + 1, i, "kdc", 3))
                {
                  SKIP_WS (line, last_element, i + 3, i);
                  if (line[i] == '=')
                    {
                      SKIP_WS (line, last_element, i + 1, i);
                      ALLOCATE_AND_CHECK (*kdc, char, (last_element - i) + 1,
                                          result);
                      for (j = i; j <= last_element; j++)
                        {
                          (*kdc)[j - i] = line[j];
                        }

                      result = O_KRB5_SUCCESS;
                      goto result;
                    }
                }
            }
        }
    }

result:
  if (result != O_KRB5_CONF_NOT_FOUND)
    {
      fclose (file);
    }
  return result;
}

#define CHECK_FPRINTF(result, writer, fmt, ...)   \
  do                                              \
    {                                             \
      if (fprintf (writer, fmt, __VA_ARGS__) < 0) \
        {                                         \
          result = O_KRB5_UNABLE_TO_WRITE;        \
          goto result;                            \
        }                                         \
    }                                             \
  while (0)
// Adds realm with the given kdc into krb5.conf
OKrb5ErrorCode
o_krb5_add_realm (const OKrb5Credential *creds, const char *kdc)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  FILE *file = NULL, *tmp = NULL;
  char line[MAX_LINE_LENGTH] = {0};
  char tmpfn[MAX_LINE_LENGTH] = {0};
  int state, i;
  char *cp = (char *) creds->config_path.data;
  char *realm = (char *) creds->realm.data;
  if ((file = fopen (cp, "r")) == NULL)
    {
      if ((file = fopen (cp, "w")) == NULL)
        {
          result = O_KRB5_CONF_NOT_CREATED;
          goto result;
        }
      CHECK_FPRINTF (result, file, "[realms]\n%s = {\n  kdc = %s\n}\n", realm,
                     kdc);
      goto result;
    }
  snprintf (tmpfn, MAX_LINE_LENGTH, "%s.tmp", cp);
  if ((tmp = fopen (tmpfn, "w")) == NULL)
    {
      result = O_KRB5_TMP_CONF_NOT_CREATED;
      goto result;
    }
  state = 0;
  while (fgets (line, MAX_LINE_LENGTH, file))
    {
      fputs (line, tmp);
      if (state == 0)
        {
          SKIP_WS (line, MAX_LINE_LENGTH, 0, i);
          if (IS_STR_EQUAL (line, MAX_LINE_LENGTH, i, "[realms]", 8) == 1)
            {
              CHECK_FPRINTF (result, tmp, "%s = {\n  kdc = %s\n}\n", realm,
                             kdc);
              state = 1;
            }
        }
    }

  if (rename (tmpfn, cp) != 0)
    {
      result = O_KRB5_TMP_CONF_NOT_MOVED;
    }

result:
  if (tmp != NULL)
    fclose (tmp);
  if (file != NULL)
    fclose (file);
  return result;
}

OKrb5ErrorCode
o_krb5_authenticate (const OKrb5Credential credentials, OKrb5Element **element)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;

  // probably better to use heap instead?
  krb5_context ctx;
  krb5_principal me;
  krb5_creds creds;

  GUARD_NULL (*element, result);
  if ((result = krb5_init_context (&ctx)))
    {
      result = result + O_KRB5_ERROR;
      goto result;
    }

  if ((result = krb5_build_principal (ctx, &me, credentials.realm.len,
                                      (char *) credentials.realm.data,
                                      credentials.user, NULL)))
    {
      result = result + O_KRB5_ERROR;
      goto result;
    };

  if ((result = krb5_get_init_creds_password (
         ctx, &creds, me, (char *) credentials.user.password.data, NULL, NULL,
         0, NULL, NULL)))
    {
      result = result + O_KRB5_ERROR;
      goto result;
    }
  ALLOCATE_AND_CHECK (*element, OKrb5Element, 1, result);
  (*element)->me = me;
  (*element)->creds = creds;
  (*element)->ctx = ctx;

result:
  if (result != O_KRB5_SUCCESS)
    {
      krb5_free_principal (ctx, me);
      krb5_free_context (ctx);
      if (*element != NULL)
        {
          free (*element);
          *element = NULL;
        }
    }

  return result;
}

void
o_krb5_free_element (OKrb5Element *element)
{
  if (element != NULL)
    {
      krb5_free_cred_contents (element->ctx, &element->creds);
      krb5_free_principal (element->ctx, element->me);
      krb5_free_context (element->ctx);
      free (element);
    }
}

OKrb5ErrorCode
o_krb5_request (const OKrb5Element *element, const char *data,
                const size_t data_len, OKrb5Data **out)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  GUARD_NOT_NULL (out, result);
  GUARD_NULL (*out, result);
  GUARD_NOT_NULL (element, result);
  ALLOCATE_AND_CHECK (*out, OKrb5Data, 1, result);
  krb5_data in_data;
  int ap_req_options = 0;

  in_data.length = data_len;
  in_data.data = (char *) data;

  if ((result = krb5_auth_con_init (element->ctx, &(*out)->auth_context)))
    {
      result = result + O_KRB5_ERROR;
      goto result;
    };

  if ((result = krb5_mk_req_extended (
         element->ctx, &(*out)->auth_context, ap_req_options, &in_data,
         (krb5_creds *) &(element->creds), &(*out)->data)))
    {
      result = result + O_KRB5_ERROR;
    };
result:
  return result;
}

OKrb5ErrorCode
o_krb5_free_data (const OKrb5Element *element, OKrb5Data *data)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  GUARD_NOT_NULL (element, result);

  if (data != NULL)
    {
      if ((result = krb5_auth_con_free (element->ctx, data->auth_context)))
        {
          result += O_KRB5_ERROR;
          goto result;
        };
      free (data);
    }
result:
  return result;
}

#if OPENVAS_KRB5_CACHED == 1
// we use FNV-1a to generate the id so that we don't need to introduce artifical
// numbers but can just reuse credentials to find connections that way we can
// simply reconnect when we either don't find an entry or when the ticket is
// invalid witout having the caller to remember artifical identifier.
static unsigned long
o_krb5_cache_credential_id (const OKrb5Credential *cred)
{
  unsigned long hash = 2166136261;
  unsigned int prime = 16777219;

  for (const char *str = cred->realm.data; *str; str++)
    {
      hash = (hash ^ *str) * prime;
    }
  for (const char *str = cred->user.user.data; *str; str++)
    {
      hash = (hash ^ *str) * prime;
    }
  for (const char *str = cred->user.password.data; *str; str++)
    {
      hash = (hash ^ *str) * prime;
    }
  return hash;
}

static OKrb5CacheList *element_cache = NULL;

OKrb5ErrorCode
o_krb5_cache_init (void)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  GUARD_NULL (element_cache, result);
  ALLOCATE_AND_CHECK (element_cache, OKrb5CacheList, 1, result);
  element_cache->cap = 2;
  ALLOCATE_AND_CHECK (element_cache->elements, OKrb5CacheElement *,
                      element_cache->cap, result);
result:
  return result;
}

OKrb5ErrorCode
o_krb5_cache_clear (void)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  size_t i;
  if (element_cache == NULL)
    goto result;
  for (i = 0; i < element_cache->len; i++)
    {
      o_krb5_free_element ((element_cache->elements[i])->element);
      free (element_cache->elements[i]);
    }
  free (element_cache);
  element_cache = NULL;

result:
  return result;
}

OKrb5CacheElement *
o_krb5_cache_find (const OKrb5Credential *cred)
{
  if (element_cache == NULL)
    {
      return NULL;
    }
  unsigned long id = o_krb5_cache_credential_id (cred);
  size_t i;

  for (i = 0; i < element_cache->len; i++)
    {
      if (element_cache->elements[i]->id == id)
        {
          return element_cache->elements[i];
        }
    }
  return NULL;
}

static OKrb5ErrorCode
o_krb5_cache_add_element (const OKrb5Credential credentials,
                          OKrb5CacheElement **out)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;

  OKrb5CacheElement **new_elements;
  if (element_cache->len == element_cache->cap)
    {
      if ((new_elements =
             realloc (element_cache->elements,
                      element_cache->cap * 2 * sizeof (OKrb5CacheElement *)))
          == NULL)
        {
          result = O_KRB5_NOMEM;
          goto result;
        }
      memset (new_elements + element_cache->cap, 0,
              element_cache->cap * sizeof (OKrb5CacheElement *));
      element_cache->cap = element_cache->cap * 2;
      element_cache->elements = new_elements;
    }

  ALLOCATE_AND_CHECK (*out, OKrb5CacheElement, 1, result);
  (*out)->credentials = &credentials;
  (*out)->id = o_krb5_cache_credential_id (&credentials);
  element_cache->elements[element_cache->len] = *out;

  if ((result = o_krb5_authenticate (credentials, &(*out)->element)))
    {
      (*out)->last_error_code = result;
      goto result;
    }
  element_cache->len += 1;

result:
  return result;
}

OKrb5ErrorCode
o_krb5_cache_authenticate (const OKrb5Credential credentials,
                           OKrb5CacheElement **out)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  GUARD_NOT_NULL (out, result);
  GUARD_NULL (*out, result);

  if (element_cache == NULL)
    o_krb5_cache_init ();
  OKrb5CacheElement *element = o_krb5_cache_find (&credentials);

  if (element == NULL)
    {
      if ((result = o_krb5_cache_add_element (credentials, &element)))
        {
          goto result;
        }
    }
  else
    {
      time_t systime;
      systime = time (NULL);
      if (systime >= element->element->creds.times.endtime)
        {
          // TODO: add renew when till is lower than systime
          o_krb5_free_element (element->element);
          element->element = NULL;
          if ((result = o_krb5_authenticate (credentials, &element->element)))
            {
              element->last_error_code = result;
              goto result;
            }
        }
    }
  *out = element;
result:
  return result;
}

OKrb5ErrorCode
o_krb5_cache_request (const OKrb5Credential credentials, const char *data,
                      const size_t data_len, OKrb5Data **out)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;

  printf ("hi: %s %d\n", __func__, __LINE__);
  if (element_cache == NULL)
    o_krb5_cache_init ();
  printf ("hi: %s %d\n", __func__, __LINE__);
  OKrb5CacheElement *element = NULL;
  if ((result = o_krb5_cache_authenticate (credentials, &element)))
    {
      goto result;
    }
  printf ("hi: %s %d\n", __func__, __LINE__);

  if ((result = o_krb5_request (element->element, data, data_len, out)))
    {
      goto result;
    }
  printf ("hi: %s %d\n", __func__, __LINE__);

result:
  return result;
}

#endif

// GSS stuff, remove rest except for REALM handling
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH 11
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID \
  "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"
#ifndef gss_mech_spnego
gss_OID_desc spnego_mech_oid_desc = {6, (void *) "\x2b\x06\x01\x05\x05\x02"};
#define gss_mech_spnego (&spnego_mech_oid_desc)
#endif

#define ARRAY_SIZE(a) (sizeof (a) / sizeof (a[0]))

struct OKrb5GSSCredentials
{
  gss_cred_id_t gss_creds;
};

struct OKrb5GSSContext
{
  gss_cred_id_t gss_creds;
  gss_ctx_id_t gss_ctx;
  gss_name_t gss_target;
  gss_OID gss_mech;
  OM_uint32 gss_want_flags;
  OM_uint32 gss_time_req;
  gss_channel_bindings_t gss_channel_bindings;
  gss_OID gss_actual_mech_type;
  OM_uint32 gss_got_flags;
  OM_uint32 gss_time_rec;
};

static OKrb5ErrorCode
okrb5_gss_authenticate (const OKrb5Credential *creds,
                        struct OKrb5GSSContext *gss_creds)
{
  char *user_principal;
  const struct OKrb5User *user = &creds->user;

  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  ALLOCATE_AND_CHECK (user_principal, char,
                      user->user.len + creds->realm.len + 2, result);
  sprintf (user_principal, "%s@%s", (char *) user->user.data,
           (char *) creds->realm.data);

  gss_name_t gss_username = GSS_C_NO_NAME;
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  // OM_uint32 dummy_min_stat;
  gss_buffer_desc userbuf = {
    .value = user_principal,
    .length = strlen (user_principal),
  };
  gss_buffer_desc pwbuf = {
    .value = user->password.data,
    .length = user->password.len,
  };
  gss_OID_desc elements[] = {
    *gss_mech_krb5,
#ifdef __USE_IAKERB
    *gss_mech_iakerb,
#endif /* __USE_IAKERB */
    *gss_mech_spnego,
  };
  gss_OID_set_desc creds_mechs = {
    .elements = elements,
    .count = ARRAY_SIZE (elements),
  };
  gss_OID_set_desc spnego_mechs = {
    .elements = elements,
    .count = ARRAY_SIZE (elements) - 1, /* without gss_mech_spnego */
  };
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;

  maj_stat =
    gss_import_name (&min_stat, &userbuf, GSS_C_NT_USER_NAME, &gss_username);
  if (maj_stat != GSS_S_COMPLETE)
    {
      return O_KRB5_ERROR + maj_stat;
    }

  maj_stat = gss_acquire_cred_with_password (&min_stat, gss_username, &pwbuf, 0,
                                             &creds_mechs, GSS_C_INITIATE,
                                             &cred, NULL, NULL);

  //(void) gss_release_name (&dummy_min_stat, &gss_username);
  if (maj_stat != GSS_S_COMPLETE)
    {
      // return NT_STATUS_LOGON_FAILURE;
      return O_KRB5_ERROR + maj_stat;
    }

  // let spnego only use the desired mechs
  maj_stat = gss_set_neg_mechs (&min_stat, cred, &spnego_mechs);
  if (maj_stat != GSS_S_COMPLETE)
    {
      // failed setting neg mechs
      return O_KRB5_ERROR + maj_stat;
    }
  gss_creds->gss_creds = cred;
result:
  // TODO: free user_principal on failure?
  return result;
}

struct OKrb5GSSContext *
okrb5_gss_init_context (void)
{
  struct OKrb5GSSContext *context = calloc (1, sizeof (struct OKrb5GSSContext));
  if (context == NULL)
    {
      return NULL;
    }
  context->gss_creds = GSS_C_NO_CREDENTIAL;
  context->gss_ctx = GSS_C_NO_CONTEXT;
  return context;
}

void
okrb5_gss_free_context (struct OKrb5GSSContext *context)
{
  if (context != NULL)
    {
      if (context->gss_creds != GSS_C_NO_CREDENTIAL)
        {
          gss_release_cred (NULL, &context->gss_creds);
        }
      // TODO: clean rest
      free (context);
    }
}

OKrb5ErrorCode
o_krb5_gss_prepare_context (const OKrb5Credential *creds,
                            struct OKrb5GSSContext *gss_context)
{
  char *target_principal_str = NULL;
  OKrb5ErrorCode result = O_KRB5_SUCCESS;

  gss_name_t gss_target = GSS_C_NO_NAME;
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  gss_buffer_desc targetbuf = GSS_C_EMPTY_BUFFER;
  const struct OKrb5Target *target = &creds->target;


  if (gss_context->gss_creds == GSS_C_NO_CREDENTIAL)
    {
      if ((result = okrb5_gss_authenticate (creds, gss_context)))
        {
          goto result;
        }
    }

  if (target->domain.len != 0)
    {
      ALLOCATE_AND_CHECK (target_principal_str, char,
                          target->host_name.len + target->domain.len
                            + target->service.len + creds->realm.len + 4,
                          result);
      sprintf (target_principal_str, "%s/%s/%s@%s",
               (char *) target->service.data, (char *) target->host_name.data,
               (char *) target->domain.data, (char *) creds->realm.data);
    }
  else
    {
      ALLOCATE_AND_CHECK (target_principal_str, char,
                          target->host_name.len + target->service.len
                            + creds->realm.len + 3,
                          result);
      sprintf (target_principal_str, "%s/%s@%s", (char *) target->service.data,
               (char *) target->host_name.data, (char *) creds->realm.data);
    }

  targetbuf = (gss_buffer_desc){
    .value = target_principal_str,
    .length = strlen (target_principal_str),
  };

  maj_stat = gss_import_name (&min_stat, &targetbuf,
                              // might also be GSS_C_NT_HOSTBASED_SERVICE,
                              // but samba uses GSS_C_NT_USER_NAME
                              GSS_C_NT_USER_NAME, &gss_target);
  if (maj_stat != GSS_S_COMPLETE)
    {
      result = O_KRB5_ERROR + maj_stat;
      goto result;
    }

  gss_context->gss_target = gss_target;
  // gss_set_neg_mechs() already specified that we want gss_mech_krb5
  // and/or gss_mech_iakerb
  // so we use spnego to do the negotiation
  gss_context->gss_mech = gss_mech_spnego;
  gss_context->gss_want_flags = GSS_C_MUTUAL_FLAG | GSS_C_DELEG_POLICY_FLAG
                                | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG
                                | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;
  gss_context->gss_got_flags = 0;
  gss_context->gss_channel_bindings = GSS_C_NO_CHANNEL_BINDINGS;
  gss_context->gss_time_req = 0;
  gss_context->gss_time_rec = 0;
  gss_context->gss_actual_mech_type = NULL;
result:
  // TODO: cleanup target_principal_str on failure?

  return result;
}

// TODO: this signature feels unintuitive based on the mix of in and out and
// changed gss_context as well...
OKrb5ErrorCode
o_krb5_gss_update_context (struct OKrb5GSSContext *gss_context,
                           const struct OKrb5Slice *in_data,
                           struct OKrb5Slice **out_data, bool *more)
{
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  // TODO: validate in data
  gss_buffer_desc in_buf = {
    .length = in_data->len,
    .value = in_data->data,
  };
  gss_buffer_desc out_buf = GSS_C_EMPTY_BUFFER;

  maj_stat = gss_init_sec_context (
    &min_stat, gss_context->gss_creds, &gss_context->gss_ctx,
    gss_context->gss_target, gss_context->gss_mech, gss_context->gss_want_flags,
    gss_context->gss_time_req, gss_context->gss_channel_bindings, &in_buf,
    &gss_context->gss_actual_mech_type, &out_buf, &gss_context->gss_got_flags,
    &gss_context->gss_time_rec);
  if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
    {
      result = O_KRB5_ERROR + maj_stat;
      goto result;
    }
  *out_data = malloc (sizeof (struct OKrb5Slice));
  (*out_data)->data = calloc (1, out_buf.length);
  memcpy ((*out_data)->data, out_buf.value, out_buf.length);
  printf ("out_buf.length: %lu\n", out_buf.length);
  (*out_data)->len = out_buf.length;

  gss_release_buffer (&min_stat, &out_buf);
  *more = maj_stat == GSS_S_CONTINUE_NEEDED;
result:
  return result;
}

OKrb5ErrorCode
o_krb5_gss_session_key_context (struct OKrb5GSSContext *gss_context,
                                struct OKrb5Slice **out)
{
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  gss_OID_desc gse_sesskey_inq_oid = {
    GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH,
    (void *) GSS_KRB5_INQ_SSPI_SESSION_KEY_OID,
  };
  gss_buffer_set_t set = GSS_C_NO_BUFFER_SET;

  maj_stat = gss_inquire_sec_context_by_oid (&min_stat, gss_context->gss_ctx,
                                             &gse_sesskey_inq_oid, &set);
  if (maj_stat != GSS_S_COMPLETE)
    {
      result = O_KRB5_ERROR + maj_stat;
      goto result;
    }

  if ((set == GSS_C_NO_BUFFER_SET) || (set->count == 0)
      || (set->elements[0].length == 0))
    {
      result = O_KRB5_ERROR + GSS_S_BAD_SIG;
      goto result;
    }

  // TODO: verify out
  *out = calloc (1, sizeof (struct OKrb5Slice));
  (*out)->data = malloc (set->elements[0].length);
  memcpy ((*out)->data, set->elements[0].value, set->elements[0].length);
  (*out)->len = set->elements[0].length;
  gss_release_buffer_set (&min_stat, &set);
result:
  return result;
}
