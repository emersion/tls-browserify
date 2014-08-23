tls-browserify
==============

`tls` module for [Browserify](https://github.com/substack/node-browserify), using [`forge`](https://github.com/digitalbazaar/forge).

Works well with [`net-browserify`](https://github.com/emersion/net-browserify), but can be used with other `net` libraries too (even the native one).

Supported APIs:
* `tls.TLSSocket`: a secure socket
* `tls.connect()`: connect to a remote server using TLS
