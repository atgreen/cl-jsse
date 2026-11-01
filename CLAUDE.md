# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:1105d646 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## Build & Test

SBCL + ocicl. Requires **OpenLDK** (`openldk/interop`) and a **JDK 25** with
`JAVA_HOME` set (OpenLDK reads the JDK's classes, crypto, and CA trust store).

```bash
# Tests (loopback TLS over real sockets; forced to TLS1.2+RSA to stay fast):
JAVA_HOME=/path/to/jdk-25 sbcl --eval '(asdf:test-system "cl-jsse/tests")'
```

During development, OpenLDK is resolved from the local checkout `~/git/openldk`
(newer than the ocicl-published release; see bead cl-jsse-8ur) via an ASDF
source-registry pointing at it. `spikes/ssleng-fast.lisp` is the standalone
handshake spike that proved `SSLEngine` works under OpenLDK.

## Architecture Overview

`cl-jsse` wraps a caller-provided Lisp byte stream in TLS using
`javax.net.ssl.SSLEngine` (the transport-agnostic TLS state machine), reached
through `openldk/interop`. There is no OpenSSL, C, or FFI — the crypto and
certificate handling are the JDK's own.

- `src/engine.lisp` — the pump: drives `SSLEngine` wrap/unwrap over the
  transport stream. Transport reads are **framed by the 5-byte TLS record
  header** (so a blocking transport never deadlocks and `unwrap` is called ~once
  per record, which matters because each Java call is a round-trip through
  OpenLDK).
- `src/streams.lisp` — the `trivial-gray-streams` binary stream and the
  client/server constructors (`SSLEngine` configured via one `SSLParameters`).
- `src/context.lisp` — `SSLContext` with key/trust managers.
- `src/certificate.lisp` — accessors over peer X.509 certs.
- `compat/cl+ssl.lisp`, `compat/pure-tls.lisp` — thin drop-in layers over the
  core (systems `cl-jsse/cl+ssl`, `cl-jsse/pure-tls`).

**Performance:** OpenLDK JIT-compiles bytecode to native via SBCL (compiling
each method on first use). The default TLS 1.3 ECDHE handshake was observed to
be very slow in testing; restrict a context to TLS 1.2 +
`TLS_RSA_WITH_AES_128_GCM_SHA256` for fast handshakes (a workaround, not a
protocol recommendation — no forward secrecy).

## Conventions & Patterns

- Interop idioms come from `openldk.interop` (`java-call`, `java-static`,
  `java-new`, `jstring`/`lstring`, `make-java-array-of`, `with-foreign-errors`),
  used the way `~/git/cl-jdbc` does.
- Compat layers **refuse** security-relevant options they cannot honour (a
  `:verify-callback`, encrypted keys, PEM identity/CA files) rather than
  silently ignoring them; JSSE-native `:keystore`/`:truststore` are the
  supported path.
- Use Java `SSLParameters` to set protocols/ciphers/ALPN/client-auth in one
  `setSSLParameters` call — setting them on the engine and then applying a
  separately-fetched `SSLParameters` clobbers them.
