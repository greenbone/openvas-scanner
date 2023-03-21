# API Documentation

This API describes the interface for communicating with the Scanner.
It is meant to be used by clients to control scans.
The specification is described in [OpenAPI 3.0.3](openapi.yml).
A list of tools for working with it can be found [here](https://openapi.tools/).

This document describes authentication and response headers, those cannot be specified within OpenAPI.

## Authentication

In general the API supports two kinds of authentication methods:
- API Key
- Certificates
The different authentication modes are set within a configuration file or via the argument list, when starting the server.

The authentication is required for each request except for a HEAD request.

Additionally for testing and development the authentication can be disabled.

### API Key

An API key is a token that client provides when making API requests and are used to authorize access.
The `SCANNER-API-KEY` must be in the header.

More details about this method follows with its implementation.

### Certificates

This option use [X.509](https://en.wikipedia.org/wiki/X.509), based on CA to verify derived certificates to allow access.

More details about this method follows with its implementation.

## API Response Header

The API Response Header contains additional information, which can be used by the client to verify the used version of the API.

The header contains:
- `api-version` Comma separated list of available API versions
- `feed-version` The version of the feed used for the VTs
- `authentication` Supported authentication methods

In case the version information is not available for the server, its value is set to 0.

A HEAD request will respond with an empty body and does not require any authentication.
