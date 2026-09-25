# Local execution standing for governed-loop custody

This deployment profile is Docket-local. It does not generalize Constellation
Standing, replace AG authorization or review, or grant executor success.

An operator prospectively grants one permission for an exact campaign,
occurrence, program, work schema, work, subject and scope. The grant must expire
within 300 seconds and cannot be retimed. Revocation and supersession append
immutable revisions. The resolver reads the selected revision and returns the
existing V1 standing response; it never grants on request.

This is a supported Docket component surface. A generic live composition using
it has not yet been qualified end to end with AG, an enrolled executor, and a
real operator-owned grant.

Use `docket governed-loop standing-grant` before the AG spend, supplying every
exact tuple field plus `--operator`, `--issued-at-unix-ms`, and
`--expires-at-unix-ms`. Use `standing-revoke` or `standing-supersede` with the
grant identity and a monotonic `--at-unix-ms`. Deployment tooling generates a
measured zero-argument launcher with `standing-write-launcher`; it captures the
resolver and closed static config from nonsymlink regular files, checks their
enrolled hashes, seals both memfds against content and size changes, and then
executes and reads only those sealed captures.
The launcher runs under `python -IS` (isolated mode without `site`), so no
user or system site-packages directory and no `.pth` hook is loaded; it uses
only the standard library. The selected Python interpreter and its standard
library remain trusted deployment inputs. The launcher generator observes the interpreter hash while
enrolling, but the generated script's shebang does not reverify the already
executing interpreter at runtime; deployment enrollment must pin it separately.

## Commands

Prospectively enroll the exact tuple before AG spends:

```sh
docket governed-loop standing-grant --state /absolute/docket-state \
  --operator docket-local-operator \
  --campaign sha256:... --occurrence 00000000-0000-4000-8000-000000000000 \
  --program sha256:... --work-schema maude.reviewed-local-copy/v1 \
  --work sha256:... --subject sha256:... --scope sha256:... \
  --issued-at-unix-ms 1700000000000 --expires-at-unix-ms 1700000300000

docket governed-loop standing-revoke --state /absolute/docket-state \
  --execution-standing sha256:... --at-unix-ms 1700000001000
# standing-supersede accepts the same identity and time arguments.
```

These are parameterized command shapes, not a copy-paste current grant. The
shown numeric timestamps are illustrative and expired; derive fresh monotone
times for the selected local job without exceeding 300 seconds.

The closed resolver config names the same Docket database, not a second
authority or consumption ledger:

```json
{"operator":"docket-local-operator","schema":"docket.governed-loop.local-standing-resolver-config/v1","state_database":"/absolute/docket-state/state.sqlite"}
```

Generate the create-once launcher using an absolute, nonsymlink interpreter:

```sh
docket governed-loop standing-write-launcher \
  --resolver /absolute/bin/docket-local-standing-resolver \
  --config /absolute/fixed/local-standing-resolver.json \
  --python-interpreter /absolute/nonsymlink/python3 \
  --output /absolute/fixed/docket-local-standing-launcher
```

The enrolled AG Docket port owns and invokes acceptance once. The command below
is its process-transport reference, not an instruction to deliver manually
after or alongside an AG finite run. The local-mode flag is an
optional setup assertion after enrollment; omitting it cannot downgrade an
enrolled state database:

```sh
docket governed-loop accept --state /absolute/docket-state \
  --trust /absolute/fixed/ag-issuer-trust.json \
  --standing-resolver /absolute/fixed/docket-local-standing-launcher \
  --executor /absolute/fixed/reviewed-executor \
  --executor-config /absolute/fixed/reviewed-executor.json \
  --require-local-standing-snapshot < signed-issuance.json

docket governed-loop standing-snapshot --state /absolute/docket-state \
  --issuance sha256:...
```

Snapshot inspection opens only an existing `state.sqlite` read-only. A missing
state path is an error and is not created or migrated.

The first prospective grant irreversibly enrolls that Docket state database in
local snapshot-currentness mode and fixes its operator identity and 300-second
maximum. Every later accept against that state requires local backing even when
the caller omits `--require-local-standing-snapshot`; the flag only asserts the
expected mode on a not-yet-enrolled database and cannot select weaker behavior.
Docket requires the exact immutable revision named by the resolver's hashes and
stores its permission identity, revision,
resolution time, expiry, currentness and resolution atomically with custody.
The currentness digest commits the permission identity, immutable revision
identity, status, resolution time and expiry; the resolution digest additionally
commits the subsequently authenticated AG issuance.
`governed-loop standing-snapshot --issuance DIGEST` reads that explicit backing
receipt. Older external-resolver V1 custody remains readable and has no invented
local snapshot.

## Declared currentness bound

Snapshot currentness is the approved rule, and it is a declared bound, not an
open-ended one. A revocation committed after a successful resolution is
non-retroactive for that custody attempt: a concurrent revocation appends a new
revision and does not mutate the exact revision already observed and retained
with custody. That non-retroactivity holds only inside this interval:

| Bound | Value | Where checked |
|---|---|---|
| Resolution age (`now - resolved_at`) | at most 30 000 ms (`MAX_STANDING_SNAPSHOT_AGE_MS`) | at resolution, again immediately before the custody transaction, and again immediately before `execute` |
| Grant expiry | `now < expires_at` (grant lifetime at most 300 s) | the same three points |
| Resolution to custody | at most 30 s (the age bound); the local-mode resolver deadline is 5 s | immediately before the custody transaction |
| Custody to executor dispatch | resolution to dispatch at most 30 s | immediately before `execute` |
| Revocation latency | a revocation committed at time `r` stops every dispatch that begins after `r + 30 s`; an earlier dispatch may rely on a resolution taken before `r` | follows from the age bound |

Every check uses one injected clock. Before custody, a failed check refuses and
persists nothing, so no standing use is consumed:
`governed-execution-standing-snapshot-stale` or
`governed-execution-standing-expired`. After custody it records the attempt
`indeterminate` with evidence
`docket.governed-loop.standing-snapshot-exceeded-before-execute/v1` and never
invokes the executor. A resolver answer older than the bound is refused even
though the grant window still contains it.

The bound covers when the effect may begin. It does not bound how long an
executor runs once it is dispatched.

Before resolution, absent, revoked, superseded, expired, future-dated, ambiguous
or mismatched permission state fails closed. `accept` keeps these refusals
distinct: `governed-execution-standing-absent`, `-revoked`, `-superseded`,
`-expired` and `-not-current` (future-dated). After custody, executor
uncertainty uses the retained same-attempt reconciliation path and never
re-resolves standing or redispatches mechanics.

## AG issuance not-after

The local grant is Docket's own warrant. The AG warrant is carried by the signed
issuance. Custody requires `ag.governed-loop.issuance/v2`, whose
`not_after_unix_ms` is part of both AG's identity digest and the signed body.
Docket enforces `now < not_after` with the same clock at the three points
above. A retry, re-delivery or reconciliation cannot refresh it: the value is
signed and identity-bound, so a different value is a different issuance that
only AG's key could produce. AG rebuilds its issuance deterministically from the
spend and never re-mints, and once custody exists for an AG spend Docket refuses
any other issuance for that spend. Expiry before custody refuses as `governed-issuance-expired`.
Expiry after custody records `indeterminate` with evidence
`docket.governed-loop.issuance-expired-before-execute/v1` and does not execute.
A historical `ag.governed-loop.issuance/v1` (alpha.6 and earlier) has no
not-after. It is refused for new custody as `governed-issuance-not-after-absent`.
Custody already retained under v1 still verifies, inspects and reconciles:
verifying a record is not dispatching it. The identity, canonical bytes and
signature law are pinned by `conformance/ag-governed-loop-issuance/v2-vectors.json`,
a byte-for-byte mirror of AG's corpus.

Revocation of an AG issuance is not implemented. A short not-after limits how
long a withdrawn AG decision can still reach an effect, but expiry is not
revocation.
