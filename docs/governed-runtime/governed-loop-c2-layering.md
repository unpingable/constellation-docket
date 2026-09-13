# Governed-loop C2 layering and qualification

## Campaign boundary

C2 changes only the internal ownership of Docket's governed-loop implementation. It does not change the frozen `docket.governed-executor-transport/v1` contract, any governed-loop wire shape, custody authority, persistence schema, or executor mechanics.

Starting custody:

- repository: `/home/jbeck/git/docket/runtime`
- branch: `campaign/c1-executor-transport-canonicalization`
- HEAD: `ab8f90ba26362529c3aff341d325d4eaee9a271d`
- worktree: clean
- `Cargo.toml`: `ac94353a1a602d2803bc69926bc107350cbb9c69e7437ff563cebe69bce731ba`
- `Cargo.lock`: `fba338c18195dc957491fa76400b3b842bfbb6c0b7356bfe4d3a23093dd37d3f`
- C1 specification: `b54f8db4d89c7e422733757f7a69b7fcc7420ce225f782f493c703c8e39e41a1`
- C1 adjudication: `1aca787c6cfe2704803082b0d16dee51795400194d7432f017d2c7ca326d27cf`
- C1 corpus: `3e58081f79c73333e7371210c389e6a25e7458e2f6901169ed3252738b8cf687`
- C1 corpus manifest: `7d2d94ab025bc8f8c13d6df29114458ed1680624e8f30d20cd294b55ee21adbd`
- SQLite migration `0006_governed_loop_custody.sql`: `eefe9b084d1515086d3de3621c8b52a95a1603622f23482d2e700242bb7caeeb`

The bounded implementation branch is `campaign/c2-governed-loop-layering`.

## Before map

At the C1 baseline, `crates/gwr-local/src/governed_loop.rs` owned every layer in one module:

| Concern | Baseline implementation | Classification |
| --- | --- | --- |
| Governed-loop wire values and schema identities | V1 structs, enums, and constants | pure domain/wire contract |
| Digest validation, issuance/standing validation, attempt/marker derivation, replay envelope equivalence | `require_digest`, `validate_issuance`, `validate_standing`, `make_custody`, `require_same_envelope` | custody law |
| Accept/reconcile/inspect sequencing and outcome classification | `accept`, `reconcile`, `inspect`, `record_executor_outcome`, `response` | orchestration/coordination |
| AG issuance authentication | `verify_signed_issuance`, Ed25519 verification | local cryptographic adapter |
| Custody and settlement storage | `GovernedCustodyStoreV1` and embedded SQL | SQLite adapter mechanics |
| Standing resolution | child-process JSON invocation | local-process execution |
| Executor plan, program, and config binding | `resolve_executor_binding`, `require_executor_binding` | executable measurement/binding |
| Executor execute/reconcile | `std::process::Command`, bounded stdin/stdout JSON | local-process execution |
| File opening, `O_NOFOLLOW`, timestamps, paths | local helpers | filesystem/OS-specific mechanics |

Repository evidence supports the requested three-layer direction with one qualification: the existing pure kernel in `gwr-core` does not own the governed-loop's external JSON projection. Moving the C1 wire structs there would introduce serialization concerns and a second domain model into the kernel. C2 therefore leaves `gwr-core` unchanged and puts the transport-neutral V1 values and law in `gwr-runtime`.

## After map and dependency direction

```text
gwr-core
  pure existing kernel (unchanged)
       ^
       |
gwr-runtime
  governed_loop                 V1 values, identity and validation law
  ports::governed_loop          narrow custody/resolver/executor/clock ports
  services::governed_loop       accept/reconcile/inspect coordination
       ^
       |
gwr-local
  governed_loop                 compatibility API plus concrete adapters
    SQLite | Ed25519 | clock | paths | measurement | local child processes
```

The runtime layer has no dependency on `gwr-local`, SQLite, `ring`, `libc`, filesystem APIs, or process APIs. `gwr-local` implements the four governed-loop ports. No new cross-repository runtime dependency or dependency cycle is introduced.

`serde`, `serde_json`, and `sha2` are direct `gwr-runtime` dependencies because the exact closed V1 wire projection and its existing domain-separated identity rules are runtime-owned law. All three were already locked workspace dependencies; C2 adds no package version to `Cargo.lock`.

## Exact ownership moves

Moved from `gwr-local::governed_loop` to `gwr_runtime::governed_loop`:

- all governed-loop V1 constants, wire structs, and enums;
- `ExecutorBindingV1` and `CustodyRecordV1`;
- domain-separated hashing and digest-syntax validation;
- issuance and standing validation;
- exact-envelope replay validation;
- custody and executor-dispatch derivation.

Moved to `gwr_runtime::ports::governed_loop`:

- `GovernedCustodyStoreV1`;
- `ExecutionStandingResolverV1`;
- `GovernedExecutorV1`;
- `GovernedClockV1`.

Moved to `gwr_runtime::services::governed_loop`:

- accept, reconcile, and inspect sequencing;
- generic attempt/marker/receipt outcome binding;
- generic known/indeterminate result classification;
- reconciliation response construction.

Retained in `gwr-local::governed_loop`:

- signed issuance parsing and Ed25519 trust verification;
- SQLite opening, schema use, transactions, queries, and row decoding;
- durable settlement and indeterminate writes;
- local clock;
- executable/config/plan measurement and binding;
- path and regular-file requirements;
- `std::process::Command` invocation;
- the 1 MiB stdout bound and local transport error plumbing;
- base64, SQL conversion, and OS helpers.

## API and compatibility decision

The existing `gwr_local::governed_loop` public functions remain wrappers with their original signatures. Its public V1 types and constants are compatibility re-exports of the runtime-owned definitions, so current callers retain source compatibility while there is only one Rust definition.

These re-exports are intentionally bounded to the existing governed-loop V1 surface. New transport-neutral callers should use `gwr_runtime`; local executable callers may continue to use `gwr_local`. Removing the compatibility path is not part of C2.

## Semantic and authority invariants

The acceptance sequence remains: verify the signed envelope locally; check exact replay; bind the executor; obtain time; resolve fresh standing; derive and transactionally persist custody; remeasure the binding; invoke once; classify and persist the result.

The reconciliation sequence remains: validate identity; load custody; enforce optional exact attempt binding; replay a settled terminal record without executor access; remeasure the executor; invoke only `reconcile`; record evidence-sensitive known or indeterminate state; reread durable state; return its exact projection.

Docket continues to own execution standing consumption, attempt identity and custody, executor binding, settlement, and reconciliation. No AG authority, executor-specific effect semantics, ManagedFile semantics, VM lifecycle, or campaign orchestration moved into Docket.

The C1 specification and corpus remain external invariants. C2 neither edits their files nor adds an in-band schema tag to the closed V1 dispatch/outcome objects.

## Persistence and fault qualification

The SQLite migration is byte-identical to the C1 baseline. C2 requires no migration. A new compatibility witness verifies the migration identity and the exact semantic contents of both governed-loop tables after acceptance.

The pre-existing governed-loop suite remains the behavioral oracle and covers exact replay, standing consumption, changed standing, signature/plan/program substitution, duplicate custody, indeterminate recovery, reconciliation, persisted-row tamper detection, C1 corpus projection, and oversized executor output. Added C2 witnesses cover:

- restart before custody reservation without state or invocation;
- restart after durable custody caused by transport refusal, with reconciliation and no second execute;
- executable replacement after reservation and before invocation;
- exact terminal failure and settlement replay;
- changed attempt/marker outcome binding and stored work/subject/scope substitution;
- unchanged SQLite schema and exact row meanings.

## Qualification record

The qualified implementation commit is `f7a0018` (`Restore governed-loop runtime layering`). The exact implementation tree passed:

```text
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p gwr-local governed_loop
cargo test -p gwr-local docket_owned_executor_transport_corpus_matches_the_v1_wire_projection
cargo test --workspace
cargo test --workspace --release
```

Results:

- formatting: pass;
- clippy for every workspace target with warnings denied: pass;
- targeted governed-loop suite: 17 passed, 0 failed;
- targeted C1 transport corpus projection: 1 passed, 0 failed;
- full debug workspace: 279 passed, 0 failed;
- full release workspace: 279 passed, 0 failed.

Before any C2 edit, the 11 pre-existing governed-loop tests passed at the C1 baseline. All 11 remain green after the move; the six additional C2 witnesses account for the targeted total of 17.

After qualification, `sha256sum -c conformance/executor-transport-v1/SHA256SUMS` passed. The C1 specification, adjudication, dispatch schema, outcome schema, corpus, and manifest retained their starting SHA-256 identities. The SQLite migration retained `eefe9b084d1515086d3de3621c8b52a95a1603622f23482d2e700242bb7caeeb`.

The root manifest remained `ac94353a1a602d2803bc69926bc107350cbb9c69e7437ff563cebe69bce731ba`. `Cargo.lock` changed from `fba338c18195dc957491fa76400b3b842bfbb6c0b7356bfe4d3a23093dd37d3f` to `c8753bcca410fbbf6617f630e4d439b1db929c54829aeff7591b5216fbe39ed2`; its only semantic change is recording the already-locked `serde`, `serde_json`, and `sha2` dependencies under `gwr-runtime`.

No persistence migration, external transport change, authority movement, or observable recovery-class change was found.

## Outside C2

- Whether to retire the compatibility re-exports is a future API lifecycle choice, not required for correct layering.
- AG pure-model executor ownership remains the separate follow-up identified by C1.
- Generalized executor frameworks, remote/VM adapters, historical campaign cleanup, and repository restructuring were not begun.

Classification: `LAYERING-RESTORED-WITH-COMPATIBILITY-QUALIFICATION`.
