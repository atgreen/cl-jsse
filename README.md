# cl-jsse

TLS for Common Lisp over Java's **JSSE** (`javax.net.ssl`), running on
[OpenLDK](https://github.com/gastownhall/openldk).

`cl-jsse` wraps a caller-provided Lisp byte stream in TLS, driving the handshake
and record layer with `javax.net.ssl.SSLEngine` — the transport-agnostic TLS
state machine built into the JDK OpenLDK reads. There is no OpenSSL, no C
dependency, and no FFI: the crypto and certificate handling are the JDK's own,
reached through OpenLDK.

> **Status:** `cl-jsse` is **not** a performant TLS implementation and isn't
> meant to be one. It's a proof-of-technology for OpenLDK — a demonstration that
> a real, security-sensitive JDK subsystem (JSSE) can be driven from Common Lisp
> through OpenLDK. For production TLS, reach for [cl+ssl](https://github.com/cl-plus-ssl/cl-plus-ssl)
> or [pure-tls](https://github.com/atgreen/pure-tls).

It offers three APIs:

- **`cl-jsse`** — the native API: a `trivial-gray-streams` binary stream plus a
  context object.
- **`cl+ssl`** — a drop-in for [cl+ssl](https://github.com/cl-plus-ssl/cl-plus-ssl)'s
  public package, so Drakma / Dexador / usocket get JSSE TLS unchanged.
- **`pure-tls`** — a drop-in for [pure-tls](https://github.com/atgreen/pure-tls)'s
  public API, so code written against pure-tls can swap to the JSSE backend.

## Requirements

- SBCL with [ocicl](https://github.com/ocicl/ocicl).
- OpenLDK (pulled in as the `openldk/interop` system).
- A **JDK 25** installation, with `JAVA_HOME` pointing at it (OpenLDK reads the
  JDK's classes and crypto providers). The TLS stack, certificate parsing, and
  the system CA trust store all come from there — no jars to add.

## The native API

```lisp
(require :asdf)
(asdf:load-system "cl-jsse")

;; Client: verify the server against the system CAs (the default).
(let ((sock (usocket:socket-stream
             (usocket:socket-connect "example.com" 443
                                     :element-type '(unsigned-byte 8)))))
  (cl-jsse:with-client-stream (tls sock :hostname "example.com")
    (write-sequence (babel:string-to-octets
                     (format nil "GET / HTTP/1.0~c~cHost: example.com~c~c~c~c"
                             #\Return #\Newline #\Return #\Newline #\Return #\Newline))
                    tls)
    (force-output tls)
    ;; ... read the response bytes from TLS ...
    (cl-jsse:protocol-version tls)   ; => "TLSv1.3"
    (cl-jsse:cipher-suite tls)))
```

A **context** holds the trust and identity policy; streams are opened over it:

```lisp
;; A server, identity from a PKCS12 key store.
(let ((ctx (cl-jsse:make-context :keystore "server.p12"
                                 :keystore-password "secret")))
  (cl-jsse:with-server-stream (tls client-socket-stream :context ctx)
    (handle tls)))
```

Key `make-context` options:

| Option | Meaning |
| --- | --- |
| `:verify-mode` | `+verify-none+`, `+verify-peer+`, or `+verify-required+` |
| `:keystore` / `:keystore-password` / `:keystore-type` | our identity (PKCS12 by default) |
| `:truststore` / `:truststore-password` / `:truststore-type` | CAs to trust; absent ⇒ system CAs |
| `:alpn-protocols` | ALPN protocol names to negotiate |
| `:protocols` | enabled TLS versions, e.g. `'("TLSv1.3" "TLSv1.2")` |
| `:cipher-suites` | enabled cipher-suite names |
| `:check-hostname` | endpoint identification for clients (on by default) |

Stream accessors: `peer-certificate`, `peer-certificate-chain`, `selected-alpn`,
`cipher-suite`, `protocol-version`, and the certificate helpers
`certificate-subject-common-names`, `certificate-not-before` /
`certificate-not-after`, `certificate-fingerprint`, `verify-hostname`.

## The compatibility layers

```lisp
(asdf:load-system "cl-jsse/cl+ssl")    ; defines package CL+SSL
(asdf:load-system "cl-jsse/pure-tls")  ; defines package PURE-TLS
```

These mirror the upstream public surfaces. JSSE configures identity and trust
through key stores rather than the PEM files those APIs take, so **PEM
certificate/key/CA options and other things JSSE cannot honour (a
`:verify-callback`, encrypted-key passwords, ECH) are refused with a clear
error, not silently ignored** — a silent no-op on a security-relevant option
would quietly weaken a caller that relied on it. Use the JSSE-native `:keystore`
/ `:truststore` extensions (accepted by both layers' `make-context`) instead.

## Performance note

OpenLDK JIT-compiles Java bytecode to native code (via SBCL), translating and
compiling each method the first time it runs. A full TLS 1.3 handshake exercises
a large amount of elliptic-curve (ECDHE) code, and in our testing that first
handshake was very slow — on the order of minutes — while a TLS 1.2 handshake
with RSA key exchange completed in seconds. Restricting a context to the latter
keeps handshakes fast:

```lisp
(cl-jsse:make-context :protocols '("TLSv1.2")
                      :cipher-suites '("TLS_RSA_WITH_AES_128_GCM_SHA256"))
```

This is a workaround for the observed cost, not a protocol recommendation — RSA
key exchange has no forward secrecy. The test suite uses it only to keep
handshakes fast enough to run. We haven't isolated how much of the cost is
one-time (first-use compilation of all that crypto code) versus steady-state.

## Building and testing

The handshake spike and the test suite both expect `JAVA_HOME` set to a JDK 25:

```sh
JAVA_HOME=/path/to/jdk-25 sbcl --eval '(asdf:test-system "cl-jsse/tests")'
```

`spikes/ssleng-fast.lisp` is the standalone handshake spike that first proved
`SSLEngine` works under OpenLDK (TLS 1.2 + RSA, in-process client↔server
loopback, no sockets).

## Author

Anthony Green <green@moxielogic.com>

## License

MIT. Copyright (C) 2026 Anthony Green.
