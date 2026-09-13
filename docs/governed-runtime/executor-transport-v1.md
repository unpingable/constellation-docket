# Docket governed-executor transport V1

## Ownership and scope

Docket owns `docket.governed-executor-transport/v1`, the generic local process
law by which one Docket-custodied attempt is presented to an independently
implemented executor. Individual executors own their sealed plans, mechanics,
journals, evidence, and receipt formats. AG owns governed occurrence,
admissibility, authorization, and continuation semantics.

The schemas and corpus in `conformance/executor-transport-v1/` are usable
without linking Docket runtime code. Independent consumers may duplicate
parsing and validation intentionally, but must conform to these artifacts.

This contract does not define ManagedFile semantics, an all-evidence model, a
remote transport, or VM lifecycle.

## Version and external schema identities

The transport identity is:

```text
docket.governed-executor-transport/v1
```

Its two structurally versioned, untagged JSON documents are:

```text
docket.governed-executor-dispatch/v1
docket.governed-executor-outcome/v1
```

V1 contains no in-band `schema` or `version` member. The exact closed shape is
the version discriminator. Adding a discriminator or any other member is a V1
unknown-field refusal and requires a future transport version.

## Process operations

An executor exposes exactly these operations:

```text
EXECUTOR plan-id CONFIG
EXECUTOR execute CONFIG
EXECUTOR reconcile CONFIG
```

`CONFIG` is executor-owned. Docket treats its content and interpretation as
opaque, while binding the selected executable bytes and returned plan identity.

`plan-id` receives no stdin document and prints exactly one canonical
`sha256:<64 lowercase hex>` identity, optionally followed by one LF. It must
not print another line or CR. A nonzero exit is refusal.

`execute` and `reconcile` receive one dispatch on stdin. A successful process
prints one outcome on stdout. A nonzero exit, malformed/oversized stdout, or
process failure is transport refusal, not an executor outcome. `reconcile`
must not invoke mechanics.

## Dispatch

The dispatch has exactly six required string members:

| Member | Meaning |
|---|---|
| `attempt` | Docket-owned attempt identity |
| `marker` | executor-local idempotency marker issued by Docket for that attempt |
| `work_schema` | exact executor-specific work type |
| `work` | exact sealed plan/work identity |
| `subject` | exact governed subject |
| `scope` | exact governed scope |

All members except `work_schema` are canonical `sha256:<64 lowercase hex>`
text. `work_schema` is nonempty and must equal the exact schema admitted by the
selected executor plan.

The five digest-valued bindings are indivisible. A prior record for the same
attempt with any different marker, work, subject, or scope is a substitution
refusal and mechanics must not run. The selected executor additionally checks
`work_schema`, work, subject, and scope against its sealed plan.

Docket issues marker uniqueness. Cross-attempt marker reuse is outside valid
Docket output. V1 does not require an executor-wide marker index, though an
executor may refuse reuse as a stronger local invariant.

## Outcome

The outcome has exactly four required members:

| Member | Meaning |
|---|---|
| `attempt` | exact dispatch attempt |
| `marker` | exact dispatch marker |
| `receipt` | executor-owned mechanics receipt or indeterminate-evidence digest |
| `outcome` | `success`, `failure`, or `indeterminate` |

The three identity members use canonical SHA-256 text. Docket treats the
receipt's internal schema as opaque. It requires exact attempt/marker binding
and digest syntax, and it prevents a different terminal result from replacing
an already retained result.

`success` means qualified durable evidence proves the exact governed effect
occurred. `failure` means qualified durable evidence proves it did not occur
or reached a definite terminal failure. `indeterminate` means neither result
can be proved. These meanings are exclusive; uncertainty is never encoded as
failure.

## JSON and boundedness

Input is UTF-8, duplicate-free semantic JSON. Object member ordering and
otherwise insignificant whitespace are not significant. Unknown members,
missing members, duplicate members, wrong types, invalid digest text,
malformed JSON, and trailing non-whitespace input refuse.

Dispatch stdin and outcome stdout are each limited to 1,048,576 bytes.
Executors emit the outcome as integer-only RFC 8785 JCS followed by LF. Input
need not already be JCS. Neither dispatch nor outcome bytes have a V1 transport
digest identity.

## Replay, restart, and reconcile

- Identical replay of a terminal attempt returns the identical outcome and
  does not repeat mechanics.
- Conflicting replay of the same attempt refuses and does not run mechanics.
- A fresh valid attempt may execute once after its executor-local reservation
  is durable.
- Restart recovery is decided from qualified persistent evidence, not from a
  nominal crash-point label. Proved effect yields `success`; proved
  non-occurrence or terminal failure yields `failure`; otherwise it yields
  `indeterminate`.
- `reconcile` reads that evidence without invoking mechanics and returns the
  result required by the preceding rule.
- Missing attempt evidence makes `reconcile` refuse. It does not imply failure.
- A transport refusal after Docket has committed custody yields Docket's
  existing indeterminate custody/reconciliation posture.

## Forward and backward behavior

A V1 consumer accepts only the V1 closed shapes. A future V2 document is not
silently treated as V1. V2 requires a distinct external schema identity and a
deliberate compatibility path. V1 artifacts retain their existing field bytes,
plan identities, executor receipt identities, and qualified evidence meaning.
