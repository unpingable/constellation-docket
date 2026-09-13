# AGENTS.md — Working in this repo

This file is a **travel guide**, not a law.
If anything here conflicts with the user's explicit instructions, the user wins.

> Instruction files shape behavior; the user determines direction.

---

## Repository scope

The Git root is this directory. It is the publishable product.

The parent directory is **local campaign custody and is not part of this repository**:
`ACTION_PLAN.md`, `archive/`, `corrected_greenfield_codex_plan.md`, `normative-packet/`,
`PACKET_CONFIRMATION_RECORD.md`. Documents here cite the normative packet as an external
source; that is a citation, not a broken link. Do not move the Git root upward, import the
parent materials, or restructure the workspace to make it look conventional.

## Quick start

```bash
cargo build --workspace
cargo test --workspace
cargo run -p gwr-local --bin docket -- --help
```

## The four gates

All four are required. Pass/fail is decided by **exit codes**, never by reading the tail
of the output.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

The release run is not redundant. A defect was shipped once whose behaviour differed
between profiles: a `debug_assert!` panicked in debug on operator-supplied input while
release silently accepted it. If you filter output, preserve the real status
(`set -o pipefail`, then read `${PIPESTATUS[0]}`) — a pipeline ending in `tail` or `grep`
returns the last command's exit code, not the test runner's.

## Safety and irreversibility

Do not do these without explicit user confirmation:

- **Do not move, delete, or force-update the `gwr-greenfield-v0.1` tag.** It identifies the
  audited frozen object. Later documentation and publication commits are expected; the tag
  stays where it is.
- Push to remote, create or close PRs and issues.
- Delete or rewrite Git history; `--force` or `--force-with-lease` pushes.
- Modify dependency files in ways that change the lock file.

## Audit history is append-only

`docs/governed-runtime/conformance-v0.md` is marked **superseded-in-part** and retains its
original classifications. `open-defects.md` retains the defects and the repair record. Do
not rewrite historical classifications, erase prior defects, or retroactively present an
audit as having found nothing. The current authoritative statement is
`conformance-v0-second-pass.md` plus the three `greenfield-*.md` deliverables.

## Claims depend on explicit premises

Recovery verdicts that assert non-occurrence rest on
`gwr_core::recovery::ExclusiveRefCustody` — the deployment's assertion that the governed
broker is the sole writer of the target ref from dispatch through recovery observation. It
is a required field, so no path reaches a verdict without naming it. It is **asserted, not
verified**, and no in-process check can verify it.

Do not quietly upgrade a stated premise to a claimed guarantee. If you strengthen
enforcement, update `trust-model.md`, the invariant-table custody note,
`RecoveryVerdict`'s documentation, and the boundary specimen together.

## Do not "fix" the boundary specimen

`crates/gwr-local/tests/ref_custody_boundary.rs` deliberately asserts the **unsound**
behaviour that appears when the custody premise is violated. It is an executable statement
of a boundary, not a defended security property, and not a failing test awaiting repair.
Changing it means deliberately changing the trust model with it.

## Threat model boundaries for v0.1

- Providers are **trusted code inside the host and same-UID security domain**. The runtime
  claims only that it hands providers no authority material and does not place their
  workspace adjacent to it. It does **not** claim OS-level confinement, and lack of
  same-UID confinement is not a defect against these claims.
- The broker binary is not a privilege boundary; anything able to run it could run
  `git update-ref` directly.
- Expiry is judged against runtime clock readings, so monotone time is an environment
  assumption.

Full statement: `docs/governed-runtime/trust-model.md`.

## No broad refactors during audit or freeze work

Keep changes small and reviewable. Do not bundle refactors, renames, or layout changes
into a repair or audit commit — a diff that mixes them cannot be reviewed against the
invariant it claims to fix. Separate publication and documentation commits from
implementation commits.

## Repository layout

```
crates/gwr-core      pure domain: identities, digests, lifecycle, bridges, refusals. No I/O.
crates/gwr-runtime   ports and services. Holds no authority of its own.
crates/gwr-local     adapters: SQLite, Git broker + binary, token codec, providers, CLI.
docs/governed-runtime  the normative specification, audits, and freeze record.
```

## Coding conventions

- Rust 2021, workspace-pinned version and lints. `clippy::all` at warn, denied in CI.
- No `serde`, no JSON in persistence: every encoding is explicit and length-prefixed, and
  is part of the store's schema.
- Every digest is computed over an explicit versioned transcript, never over incidental
  serialization. Changing a field, label, order, or domain tag is a version bump.
- Domain types return typed refusals; they do not panic on caller input. A panic reachable
  from operator input is a defect even when it fails closed.
- Tests assert behaviour through public APIs and real subprocesses where the property is
  about real process death.

## Campaign selection

Use Docket when work needs durable attempt custody, exact executor dispatch
evidence, or same-attempt reconciliation. Begin with
`cargo run -p gwr-local --bin docket -- --help`, this repository's operator
runbook, and an owner-approved state root and deployment profile. The executable
has one root help surface; do not assume every command implements `--help`.

For a governed-loop issuance, use `docket governed-loop inspect --state ...
--issuance ...` for read-only inspection. Classic Git-effect attempts instead
use `docket show` and `docket journal` with their actual attempt or dispatch
identities. Never substitute the classic read commands for governed-loop
custody inspection.

For prolonged work, use the campaign-approved durable producer and checkpoint.
After supervisor loss, reconcile the original retained identity before any
successor. Tool availability grants no standing or authority, and a path or
configuration argument is not authorization.
