// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#include "openvas-krb5.h"

#include <ctype.h>
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

#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH 11
// TODO: make GSS_KRB5_INQ_SSPI_SESSION_KEY_OID dynamic
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID \
  "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"

#ifndef gss_mech_spnego
gss_OID_desc spnego_mech_oid_desc = {6, (void *) "\x2b\x06\x01\x05\x05\x02"};
#define gss_mech_spnego (&spnego_mech_oid_desc)
#endif

#define ARRAY_SIZE(a) (sizeof (a) / sizeof (a[0]))

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
  FILE *file = NULL;

  // we don't know if we should free it or just override it.
  // aborting instead.
  GUARD_NULL (*kdc, result);
  if ((file = fopen ((char *) creds->config_path.data, "r")) == NULL)
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
  if (file != NULL)
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

#define CHECK_FPRINT(result, writer, fmt)  \
  do                                       \
    {                                      \
      if (fprintf (writer, fmt) < 0)       \
        {                                  \
          result = O_KRB5_UNABLE_TO_WRITE; \
          goto result;                     \
        }                                  \
    }                                      \
  while (0)

static OKrb5ErrorCode
o_krb5_write_trimmed (FILE *file, const char *prefix, const char *start,
                      const char *end)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  while (start < end && isspace ((unsigned char) *start))
    start++;
  while (end > start && isspace ((unsigned char) *(end - 1)))
    end--;
  CHECK_FPRINTF (result, file, "%s = %.*s\n", prefix, (int) (end - start),
                 start);

result:
  return result;
}

static OKrb5ErrorCode
o_krb5_write_realm (FILE *file, const OKrb5Credential *creds, const char *kdc)
{
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  CHECK_FPRINTF (result, file, "%s = {\n", (char *) creds->realm.data);
  const char *kdc_delimiter = strchr (kdc, ',');
  const char *kdc_start = kdc;
  const char *kdc_first_start = kdc_start;
  const char *kdc_first_end =
    kdc_delimiter != NULL ? kdc_delimiter : kdc + strlen (kdc);

  o_krb5_write_trimmed (file, "  kdc", kdc_first_start, kdc_first_end);
  if (kdc_delimiter != NULL)
    {
      kdc_start = kdc_delimiter + 1;
      while ((kdc_delimiter = strchr (kdc_start, ',')) != NULL)
        {
          o_krb5_write_trimmed (file, "  kdc", kdc_start, kdc_delimiter);
          kdc_start = kdc_delimiter + 1;
        }

      o_krb5_write_trimmed (file, "  kdc", kdc_start, kdc + strlen (kdc));
    }
  o_krb5_write_trimmed (file, "  admin_server", kdc_first_start, kdc_first_end);
  o_krb5_write_trimmed (file, "  master_kdc", kdc_first_start, kdc_first_end);
  CHECK_FPRINT (result, file, "\n}\n");

result:
  return result;
}

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

  if ((file = fopen (cp, "r")) == NULL)
    {
      if ((file = fopen (cp, "w")) == NULL)
        {
          result = O_KRB5_CONF_NOT_CREATED;
          goto result;
        }
      CHECK_FPRINT (result, file, "[realms]\n");
      o_krb5_write_realm (file, creds, kdc);
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
              o_krb5_write_realm (file, creds, kdc);

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
#define CHECK_MAJOR_STAT()              \
  if (maj_stat != GSS_S_COMPLETE)       \
    {                                   \
      result = O_KRB5_ERROR + maj_stat; \
      goto result;                      \
    }
  char *user_principal;
  const struct OKrb5User *user = &creds->user;
  size_t user_principal_len = user->user.len + creds->realm.len + 1;
  size_t user_principal_cap = user_principal_len + 1;

  OKrb5ErrorCode result = O_KRB5_SUCCESS;
  ALLOCATE_AND_CHECK (user_principal, char, user_principal_cap, result);
  snprintf (user_principal, user_principal_cap, "%s@%s",
            (char *) user->user.data, (char *) creds->realm.data);

  gss_name_t gss_username = GSS_C_NO_NAME;
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  // OM_uint32 dummy_min_stat;
  gss_buffer_desc userbuf = {
    .value = user_principal,
    .length = user_principal_len,
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
  CHECK_MAJOR_STAT ();

  maj_stat = gss_acquire_cred_with_password (&min_stat, gss_username, &pwbuf, 0,
                                             &creds_mechs, GSS_C_INITIATE,
                                             &cred, NULL, NULL);

  (void) gss_release_name (&min_stat, &gss_username);
  CHECK_MAJOR_STAT ();

  // let spnego only use the desired mechs
  maj_stat = gss_set_neg_mechs (&min_stat, cred, &spnego_mechs);
  CHECK_MAJOR_STAT ();
  gss_creds->gss_creds = cred;
result:
  if (user_principal != NULL)
    free (user_principal);
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
  OM_uint32 min_stat;
  if (context != NULL)
    {
      if (context->gss_creds != GSS_C_NO_CREDENTIAL)
        {
          gss_release_cred (&min_stat, &context->gss_creds);
        }
      if (context->gss_ctx != GSS_C_NO_CONTEXT)
        {
          gss_delete_sec_context (&min_stat, &context->gss_ctx, GSS_C_NO_BUFFER);
        }
      if (context->gss_target != GSS_C_NO_NAME)
        {
          gss_release_name (&min_stat, &context->gss_target);
        }
      if (context->gss_mech != NULL)
        {
          gss_release_oid (&min_stat, &context->gss_mech);
        }
      if (context->gss_channel_bindings != GSS_C_NO_CHANNEL_BINDINGS)
        {
          gss_release_buffer (
            NULL, &context->gss_channel_bindings->initiator_address);
          gss_release_buffer (&min_stat,
                              &context->gss_channel_bindings->acceptor_address);
          gss_release_buffer (&min_stat,
                              &context->gss_channel_bindings->application_data);
          free (context->gss_channel_bindings);
        }
      if (context->gss_actual_mech_type != NULL)
        {
          gss_release_oid (&min_stat, &context->gss_actual_mech_type);
        }
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
  if (target_principal_str != NULL)
    free (target_principal_str);

  return result;
}

OKrb5ErrorCode
o_krb5_gss_update_context (struct OKrb5GSSContext *gss_context,
                           const struct OKrb5Slice *in_data,
                           struct OKrb5Slice **out_data, bool *more)
{
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  OKrb5ErrorCode result = O_KRB5_SUCCESS;
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
  if ((*out_data = malloc (sizeof (struct OKrb5Slice))) == NULL)
    {
      result = O_KRB5_NOMEM;
      gss_release_buffer (&min_stat, &out_buf);
      goto result;
    }
  // transfers ownership of out_buf.value into out_data->data.
  // This simplifies the code as we don't have to alloc and check if the system
  // had sufficient memory and don't have to memcpy.
  (*out_data)->data = out_buf.value;
  (*out_data)->len = out_buf.length;

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

  *out = calloc (1, sizeof (struct OKrb5Slice));
  (*out)->data = malloc (set->elements[0].length);
  memcpy ((*out)->data, set->elements[0].value, set->elements[0].length);
  (*out)->len = set->elements[0].length;
  gss_release_buffer_set (&min_stat, &set);
result:
  return result;
}

char *
okrb5_error_code_to_string (const OKrb5ErrorCode code)
{
#define HEAP_STRING(var, s)              \
  do                                     \
    {                                    \
      var = calloc (1, strlen (s) + 1);  \
      snprintf (var, strlen (s) + 1, s); \
      goto result;                       \
    }                                    \
  while (0)

  char *result = NULL;
  switch (code)
    {
    case O_KRB5_SUCCESS:
      HEAP_STRING (result, "success");
    case O_KRB5_CONF_NOT_FOUND:
      HEAP_STRING (result, "krb5.conf not found");
    case O_KRB5_CONF_NOT_CREATED:
      HEAP_STRING (result, "krb5.conf not created");
    case O_KRB5_TMP_CONF_NOT_CREATED:
      HEAP_STRING (result, "tmp krb5.conf not created");
    case O_KRB5_TMP_CONF_NOT_MOVED:
      HEAP_STRING (result, "tmp krb5.conf not moved");
    case O_KRB5_REALM_NOT_FOUND:
      HEAP_STRING (result, "realm not found");
    case O_KRB5_EXPECTED_NULL:
      HEAP_STRING (result, "expected null");
    case O_KRB5_EXPECTED_NOT_NULL:
      HEAP_STRING (result, "expected not null");
    case O_KRB5_UNABLE_TO_WRITE:
      HEAP_STRING (result, "unable to write");
    case O_KRB5_NOMEM:
      HEAP_STRING (result, "no memory");
    default:
      if (code >= O_KRB5_ERROR)
        {
          int maj_stat = code - O_KRB5_ERROR;
          OM_uint32 min_stat;
          gss_buffer_desc msg;
          OM_uint32 msg_ctx = 0;

          (void) gss_display_status (&min_stat, maj_stat, GSS_C_GSS_CODE,
                                     GSS_C_NULL_OID, &msg_ctx, &msg);
          // Instead of calling gss_release_buffer, we transfer ownership of
          // msg.value (a heap-allocated string) directly to result.
          // The caller is responsible for freeing result later, this conforms
          // to other values as well.
          //
          // msg itself is stack-allocated, but msg.value is dynamically
          // allocated, so we must not call gss_release_buffer on msg after
          // ownership transfer.
          result = msg.value;
        }
      else
        {
          goto result;
        }
    }
result:
  return result;
}
