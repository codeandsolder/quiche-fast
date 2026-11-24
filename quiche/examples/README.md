# Rust examples

Run the local HTTP/0.9 or HTTP/3 pair from the `quiche` package directory,
using the repository's pinned compiler:

```sh
cargo run --locked --example server -- /path/to/document/root
cargo run --locked --example client -- https://127.0.0.1:4433/file
```

For HTTP/3, use `http3-server` and `http3-client` instead. The server
listens on loopback UDP port 4433, accepts an optional document root
(default `examples/root`), and uses the packaged example TLS identity.
Clients disable certificate verification for that demonstration identity;
these examples are not production application servers.

The QPACK examples convert tab-separated header fields (blank lines
separate field sections) to records containing a big-endian eight-byte
stream ID, a big-endian four-byte payload length, and a static-only QPACK
field section. A final nonempty section at EOF does not need a blank line.
The decoder rejects truncated records and ignores stream-zero dynamic-table
instructions.

```sh
cargo run --locked --example qpack-encode -- headers.txt > headers.bin
cargo run --locked --example qpack-decode -- headers.bin
cargo test --locked --examples
```

How to build C examples
-----------------------

### Requirements

You will need the following libraries to build the C examples in this directory.
You can use your OS package manager (brew, apt, pkg, ...) or install them from
source.

- [libev](http://software.schmorp.de/pkg/libev.html)
- [uthash](https://troydhanson.github.io/uthash/)

### Build

Simply run `make` in this directory.

```
% make clean
% make
```
