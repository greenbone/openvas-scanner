# Krb5 functions

## General

Functions related to krb5 (Kerberos).

## Table of contents

- **[krb5_error_code_to_string](krb5_error_code_to_string.md)** - Returns a string representation of either the given code or the cached code.
- **[krb5_find_kdc](krb5_find_kdc.md)** - Find the KDC for a given realm.
- **[krb5_gss_init](krb5_gss_init.md)** - initialize the krb5 GSS-API library.
- **[krb5_gss_prepare_context](krb5_gss_prepare_context.md)** - Creates the initial ticket request for the krb5 GSS-API library and prepares the context for further use.
- **[krb5_gss_session_key](krb5_gss_session_key.md)** - Returns the session key or NULL if none was found.
- **[krb5_gss_update_context](krb5_gss_update_context.md)** - Updates the context with the provided data and caches the output for the application.
- **[krb5_gss_update_context_needs_more](krb5_gss_update_context_needs_more.md)** - Returns true when the previous `krb5_gss_update_context` requires further information/calls.
- **[krb5_gss_update_context_out](krb5_gss_update_context_out.md)** - Returns the data for the application to send to the service.
- **[krb5_is_failure](krb5_is_failure.md)** - Returns 1 if the last stored krb5 or given result code is a failure, 0 otherwise.
- **[krb5_is_success](krb5_is_success.md)** - Returns 1 if the last stored krb5 or given result code is a success, 0 otherwise.
