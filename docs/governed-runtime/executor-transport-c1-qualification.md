# Executor transport canonicalization C1 qualification

Status: qualified compatibility canonicalization.

## Custody

All repositories used branch
`campaign/c1-executor-transport-canonicalization`. The start and qualified
implementation revisions are:

| Repository | Start | Qualified C1 revision |
|---|---|---|
| Docket runtime | `c9f4a8a328434700b30757a7d668013d0ac63de0` | `191f51a83ce4f1708cb443ba2185d846d87fe2f1` |
| absd | `0fa64a9ca20f81ef3d80637cf65bc14f65f936f6` | `cf57f1f62a6103c71ea1d925073eac35a90d73b6` |
| AG-ng | `8c194b7eae42f10a53b063284cdc796255af09f9` | `278867fb0e5f106a6fe39fd52e14c63d6e3ca9c4` |
| campaign-driver-ng | `6ae9e836061653164b1f70b1657f2273a4845894` | `5a584b9ca8dd32d224238df35e7ab620772251e2` |

absd began and ended with its unrelated untracked
`qualification/__pycache__/governed_vertical.cpython-312.pyc` preserved. No
other repository began dirty. Cargo manifests and lockfiles retained their
starting SHA-256 identities.

## Reconstructed common law

Before modification, Docket `ExecutorDispatchWireV1` and
`ExecutorOutcomeWireV1`, absd `ExecutorDispatchV1` and `ExecutorOutcomeV1`, AG
effectd `EffectExecutorDispatchV1` and `EffectExecutorOutcomeV1`, and CDNG
`ExecutorDispatchV1` and `ExecutorOutcomeV1` already had the same closed
six-field dispatch and four-field outcome projection. All live adapters exposed
`plan-id CONFIG`, `execute CONFIG`, and `reconcile CONFIG`.

The common law is now stated externally as:

- transport `docket.governed-executor-transport/v1`;
- dispatch `docket.governed-executor-dispatch/v1`;
- outcome `docket.governed-executor-outcome/v1`;
- closed untagged structural V1 objects, with no in-band version member;
- duplicate-free semantic JSON input, exact fields/types/digest syntax, and no
  input-JCS or transport byte-identity requirement;
- canonical JCS executor output followed by LF;
- exact attempt/marker/work/subject/scope binding and same-attempt
  substitution refusal;
- Docket-owned marker uniqueness at issuance, with no generic executor-global
  marker index requirement;
- identical terminal replay without repeated mechanics;
- evidence-sensitive success, failure, or indeterminate recovery;
- read-only reconcile, and refusal for a missing attempt;
- 1 MiB stdin/outcome bounds, with oversized outcome treated as transport
  refusal and Docket indeterminate custody.

Executor configuration, sealed plans, work schemas, mechanics, journals,
receipt bodies, and receipt identities remain executor-owned and opaque to
Docket. AG occurrence, admissibility, authorization, and continuation remain
AG-owned.

## Pre-existing differences

No incompatible semantic divergence was found after adjudication.

| Difference | Classification | C1 treatment |
|---|---|---|
| AG effectd and CDNG use a store-global `UNIQUE` marker column; absd keys exact binding by attempt without such an index | executor-specific stronger mechanic | preserved |
| absd can prove failure, success, or indeterminate at distinct durable file crash cuts; AG/CDNG post-reservation records prove only ambiguity | evidence-sensitive mechanics | preserved and represented by evidence-qualified lifecycle cases |
| AG uses typed `Digest`; absd and CDNG validate strings in their own layers | independent implementation | preserved |
| AG/CDNG use explicit duplicate-rejecting JSON helpers; Docket/absd closed struct decoding rejects duplicate known members and all unknown members | independent parser mechanics | preserved and tested against one corpus |
| AG's pure campaign model also contains executor-shaped domain projections | intentional AG semantic projection pending separate ownership review | unchanged; not folded into C1 |
| Docket previously captured executor stdout without the adjudicated 1 MiB bound | qualification gap | fixed before parse; oversized witness ends indeterminate |

No deployed field, digest preimage, canonical output, plan identity, or receipt
identity changed.

## Canonical artifacts and corpus

The normative artifacts are:

- `docs/governed-runtime/executor-transport-v1.md`;
- `conformance/executor-transport-v1/dispatch.schema.json`;
- `conformance/executor-transport-v1/outcome.schema.json`;
- `conformance/executor-transport-v1/corpus.json`;
- `conformance/executor-transport-v1/SHA256SUMS`.

The transport-neutral corpus contains 16 decode cases and 17 lifecycle cases.
It covers valid dispatch and all three outcomes, noncanonical valid input,
unknown/missing/duplicate/in-band-version/malformed input, invalid digests,
exact replay, every same-attempt binding substitution, cross-attempt marker
reuse outside the Docket-issued domain, four evidence-sensitive restart
classes, Docket outcome binding refusal, terminal outcome and receipt
substitution, and both 1 MiB directions.

Each repository owns its runner and local decoding logic:

| Consumer | Binding and runner | Existing lifecycle witnesses |
|---|---|---|
| Docket | `gwr-local::governed_loop` constants and embedded corpus test | custody replay/substitution/reconcile tests plus bounded-stdout witness |
| absd | `model` constants and `tests/executor_transport_conformance.rs` | `crash_matrix`, `hostile_matrix`, and exact dispatch-custody tests |
| AG effectd | adapter constants and `crates/ag-app/tests/executor_transport_conformance.rs` | exact replay, substitution, reserved-crash, concurrency, and receipt-tamper unit tests |
| CDNG | adapter constants and `tests/executor_transport_conformance.rs` | journal replay/substitution, concurrency, and receipt-tamper unit tests |

## Qualification commands and results

The corpus path below is
`/home/jbeck/git/docket/runtime/conformance/executor-transport-v1/corpus.json`.

All four repositories passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Independent corpus runners passed:

```text
Docket: cargo test -p gwr-local executor_transport
absd: DOCKET_EXECUTOR_TRANSPORT_CORPUS=<path> cargo test --test executor_transport_conformance -- --ignored
AG: DOCKET_EXECUTOR_TRANSPORT_CORPUS=<path> cargo test -p ag-app --test executor_transport_conformance -- --ignored
CDNG: DOCKET_EXECUTOR_TRANSPORT_CORPUS=<path> cargo test --test executor_transport_conformance -- --ignored
```

Docket additionally passed the targeted bounded reader and 1,048,577-byte
stdout witnesses, then passed both required full gates on exact C1 code:

```text
cargo test --workspace --quiet
cargo test --workspace --release --quiet
```

AG and CDNG each passed `cargo test --workspace --quiet`. absd passed its
feature-correct crash qualification command outside the restricted sandbox:

```text
cargo test --workspace --features fault-injection --quiet
```

An exploratory absd `cargo test --workspace --quiet` without
`fault-injection` failed the ten crash-matrix assertions because the executor
correctly did not activate test-only crash exits. The same run under the
restricted sandbox also denied one Unix-socket fixture; that exact fixture
passed outside the sandbox. Neither observation is a C1 regression, and the
intended fault-injection-enabled suite passed in full.

`sha256sum -c conformance/executor-transport-v1/SHA256SUMS` passed. Cargo
manifest and lockfile SHA-256 values before and after were identical in every
repository, demonstrating that no common runtime dependency was added.

## Authority and compatibility result

- Docket still issues and custodies the exact attempt and marker.
- AG still owns governed occurrence and authorization/continuation semantics.
- Every executor still independently owns parsing, validation, sealed plans,
  mechanics, journals, and receipt formats.
- Docket learned no ManagedFile or CDNG mechanics.
- absd imports no AG or Docket runtime implementation.
- Porter and other evidence families were not changed.
- Existing closed V1 specimens remain structurally and semantically valid.
- Malformed, substituted, and oversized specimens refuse consistently at the
  layer responsible for them.

## Follow-ups outside C1

- Decide later whether AG's pure-model executor projections need an explicit
  documentary crosswalk to the Docket-owned transport. Moving or removing them
  would alter the AG semantic kernel and is not C1.
- C2 may separately address `gwr-local` layering. It was not begun here.
- A future V2 may add an in-band discriminator only with explicit compatibility
  and identity review.
- VM/remote transports may consume the same external corpus, but no such work
  was begun.

Classification: `CANONICALIZED-WITH-COMPATIBILITY-QUALIFICATION`.
