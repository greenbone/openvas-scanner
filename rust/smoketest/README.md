# smoke-test

Contains a small subset of functionality tests for openvasd within a controlled environment.

To build and run the tests a Makefile is provided:
- make build - builds the smoketest binary
- make run - runs a scan against an scanner API listening on http://127.0.0.1:3000 using the API KEY authentication method
- make run-with-certs - runs a scan against an scanner API listening on https://127.0.0.1:3000 using the mTLS authentication method plus API KEY

## Configuration
Independent of the usage of the certificates, the api-key is required. Therefore, `openvasd` must have an api-key set. For details on how to configure it, see the [openvasd documentation](../openvasd/README.md).

In case of running the test against a mTLS enabled `openvasd`, you need to configure the client key and cert as well in the smoke test environment. For details on how to configure it, see the [openvasd documentation](../openvasd/README.md).

For creation of the key/cert pair for mTLS authentication, see the tls section in the [openvasd documentation](../openvasd/README.md). Also, you find certificate generators in the [examples](../examples/tls)

For authenticated scans, you can set a custom target (default is 127.0.0.1), username and password.

All settings for running the smoke-tests are set via environmental variables. The next table summarize the settings availables:

|Variable|Description|Default|Mandatory|Comment|
|--------|-----------|-------|---------|-------|
|TARGET_HOSTNAME|Custom target|127.0.0.1|no|Necessary for authenticated scans|
|TARGET_USERNAME|Username for login in the target during the authenticated scan|empty string|no|Necessary for authenticated scans|
|TARGET_PASSWORD|Password for login in the target during the authenticated scan|empty string|no|Necessary for authenticated scans|
|API_KEY|API Key for authenticated communication with `openvasd`|mtls_is_preferred|yes||
|OPENVASD|Socket where openvasd listen on|127.0.0.1:3000|no|Must be specified with port|
|CLIENT_CERT|PEM file combinating public certificate and any 3rd party intermediate certificates ||yes for mTLS|Necessary for mTLS enabled|
|CLIENT_KEY|Client private key||yes for mTLS|Necessary for mTLS enabled|


## Usage

``` bash
# set env variables
export CLIENT_CERT=/tmp/cert.pem
export CLIENT_KEY=/tmp/key.pem
export OPENVASD=192.168.0.1:3000
export TARGET_HOSTNAME=192.168.10.10
export TARGET_USERNAME=user
export TARGET_PASSWORD=pass
export API_KEY=mtls_is_preferred

#build and run
make build 
make run-with-certs
```

