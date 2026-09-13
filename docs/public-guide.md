# Docket component guide

**Docket** (`constellation-docket`) keeps custody of a bounded execution after
another office has authorized it. It records the exact work and executor
binding, delivers once, and retains settlement or indeterminate evidence for
same-attempt reconciliation. The implementation keeps its established `gwr-*`
crate, `docket`/`gwr-git-broker` executable, and wire-protocol names.

Docket does not decide what work should be done, grant AG authority, judge a
review, or decide whether a consumer may rely on an outcome.

## Current scope

The frozen `gwr-greenfield-v0.1` baseline is Git-effect-specific: it governs an
atomic target-ref transition and records the premises needed for recovery.
Current source also owns the generic
[`docket.governed-executor-transport/v1`](governed-runtime/executor-transport-v1.md)
used by separately implemented executors. That transport does not make every
executor or composition recoverable; each executor retains its own plan,
mechanics, receipt, and reconciliation law.

The Docket-local prospective-standing component surface is implemented and
tested. A generic live AG/Docket/executor composition using it has not yet been
qualified. See the [local standing guide](governed-runtime/local-execution-standing.md)
and the public [Constellation Integration guide](https://unpingable.com/constellation/integration.html).

## Build and inspect

From this repository root:

```sh
cargo build --locked --workspace
test -x ./target/debug/docket
test -x ./target/debug/gwr-git-broker
./target/debug/docket --help
```

Keep `docket` and `gwr-git-broker` together unless `GWR_BROKER_BIN` names the
exact broker. The locator supplies no authority. This repository offers a
source installation path, not a package-registry promise; see
[`source-install-and-bootstrap.md`](governed-runtime/source-install-and-bootstrap.md).

The CLI exposes root help, not a guaranteed per-command `--help` interface.
Use the documented command forms for the checked-out revision.

Classic Git-effect attempts use these inspection commands:

```sh
./target/debug/docket list --state /absolute/docket-state --json
./target/debug/docket show --state /absolute/docket-state --attempt ATTEMPT --json
./target/debug/docket journal --state /absolute/docket-state --attempt ATTEMPT --json
```

An AG-governed issuance has its own read-only projection:

```sh
./target/debug/docket governed-loop inspect \
  --state /absolute/docket-state --issuance sha256:...
```

It opens existing custody state read-only. It does not create state, resolve
standing, call an executor, or reconcile.

## Docket-local prospective standing

The deployment operator may enroll one permission before AG spends. It is
bounded to an exact campaign, occurrence, program, work schema, work, subject,
scope, and at most 300 seconds. Resolution never mints a permission. Docket
atomically consumes the immutable permission identity with custody.

The parameterized operator forms are:

```sh
./target/debug/docket governed-loop standing-grant \
  --state /absolute/docket-state --operator docket-local-operator \
  --campaign sha256:... --occurrence 00000000-0000-4000-8000-000000000000 \
  --program sha256:... --work-schema IMPLEMENTED/WORK/SCHEMA \
  --work sha256:... --subject sha256:... --scope sha256:... \
  --issued-at-unix-ms ISSUED --expires-at-unix-ms EXPIRES

./target/debug/docket governed-loop standing-revoke \
  --state /absolute/docket-state --execution-standing sha256:... \
  --at-unix-ms REVOCATION_TIME

./target/debug/docket governed-loop standing-snapshot \
  --state /absolute/docket-state --issuance sha256:...
```

`standing-supersede` accepts the same identity/time form as
`standing-revoke`. The numeric examples in the detailed guide are illustrative
historical values and will be expired; calculate fresh times from the deployment
clock without exceeding 300 seconds or retiming an existing grant.

The zero-argument resolver launcher has a separate create-once setup command,
documented with its closed configuration and interpreter boundary in the
[local standing guide](governed-runtime/local-execution-standing.md).

The `governed-loop accept` command shown there is the process-port reference
owned by AG's enrolled Docket adapter. Do not manually invoke it after or
alongside an AG finite run: that would create a duplicate delivery path.

## Outcomes and recovery

Read these questions separately:

1. Did the executor report success or failure?
2. Did Docket settle that result, or is the attempt indeterminate?
3. Does the retained evidence require operator attention?

A settled record is not automatically a successful outcome. An indeterminate
record does not establish success or failure and never authorizes redispatch.
Inspect first, then reconcile the same retained attempt with the same enrolled
executor and configuration. See the
[`operator-runbook.md`](governed-runtime/operator-runbook.md) and
[`attempt-dossier.md`](governed-runtime/attempt-dossier.md).

## Trust boundary

The frozen Git baseline depends on exclusive broker custody of the target ref
during dispatch and recovery observation. That custody is a deployment premise,
not something Docket can infer. Providers and the broker are trusted code in
the same-UID host domain, and relevant clock readings are assumed monotone.
The broker is not a permission boundary, and Docket does not claim OS-level
same-UID confinement. Read the complete
[`trust-model.md`](governed-runtime/trust-model.md) before relying on a result.

The optional CLI-backed Codex preparation adapter starts its local process in
a separate process group. On timeout it uses the host's `/bin/kill` group
operation, then kills and reaps the direct child. That procedure is qualified
on Linux; it does not claim confinement of processes that leave the group.
Timeout remains provider failure, not proof of a successful preparation or
permission to repeat work. This adapter is separate from governed executor
dispatch.

The conformance record is executable engineering evidence, not a formal proof
or a discharge of deployment premises. Earlier audit documents remain history;
the current classification is
[`conformance-v0-second-pass.md`](governed-runtime/conformance-v0-second-pass.md).
