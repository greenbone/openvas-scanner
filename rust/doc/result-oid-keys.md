# Used keys for internal messages

Under some circumstances we need to send out [results](https://greenbone.github.io/scanner-api/#/scan/get_results) as either:
- Log
- Error
to the client although there is no script with a proper OID generating them.

For those cases we introduced special keys in the form of
`$SERVICE/$COMPONENT`
in `openvasd` the service is always `openvasd` while the component may differ.

Currently the keys

- `openvasd/container-image-scanner` - contains messages from the container-image-scanner component

are implemented.
