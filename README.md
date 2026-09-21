# Docket — constellation-docket

Docket tracks an authorized execution attempt, sends its exact work to an
executor, and retains the result so an interrupted attempt can be inspected
and reconciled without blindly running it again.

Start with the [Docket component guide](docs/public-guide.md) for current
execution-custody boundaries, entry points, trust premises, and recovery.

The existing `gwr-*` crate names and `docket` / `gwr-git-broker` command names
are unchanged.

The trusted runtime establishes mechanical facts only; domain modules own semantic
judgments; labor providers produce candidate artifacts and untrusted provenance. The
normative specification lives in `docs/governed-runtime/`.

The frozen Git-effect baseline admits one effect class: the atomic Git target-ref
transition, `GitRefEffect`. Within that workflow, a proposal outside it is refused
with a typed refusal *before* any standing is issued, any
reservation is created, any dispatch identity is minted, or any provider runs
([`effect-classes.md`](docs/governed-runtime/effect-classes.md)). Recovery guarantees
are properties of that class and its stated premises, not universal Docket guarantees.
Current source also supports the separate [governed executor transport](docs/governed-runtime/executor-transport-v1.md).
Its recovery behavior depends on the selected executor and tested composition.

## Status

The current immutable Constellation integration release is
[0.1.0-alpha.6](https://unpingable.com/constellation/releases/0.1.0-alpha.6/guide.html).
Its `reviewed-local-copy/v1` profile qualified one real reviewed, AG-authorized
one-use local effect under Docket custody and reconciliation. Public newcomers
reproduced the retained evidence from anonymous clones without repeating the
provider call or effect. This is a narrow profile, not a promise that every
executor, effect class, or deployment has the same qualification.

In Constellation's supported governed paths, Nightshift records observations and
proposals, `constellation-ag` authorizes exact bounded work, and Docket owns the
attempt and its execution records. `constellation-nq` supplies profile-specific
evidence admission and checks; the selected composition determines where those
checks apply. A settled attempt is not necessarily successful and does not grant
permission for another run. Docket retains the older
authorization wire contracts (`gwr:authz-request:v1`, `ag.docket-issuance:v1`)
and their conformance vectors; it does not own authorization policy, claim
admissibility, or orchestration posture — and its own reliance bridge refuses
`safe-to-merge` as permanently inadmissible.

The audited baseline is frozen as [`gwr-greenfield-v0.1`](CHANGELOG.md) — a greenfield
comparison result, built without adapting any prior implementation. It is a working
runtime with a full audit record, not a production-hardened product. Work after the tag
(the first pilot, the canonical read surface, the explicit effect-class boundary, the
upstream-authorization intake, and two completed multi-office verticals) is on
`main` and recorded in the changelog; the tag has not moved.

Maturity: **operationally reusable vertical** — the three-office run
([`vertical-01.md`](docs/vertical-01.md), 2026-07-25) and the four-office
pilot (2026-07-26, target: the Nightshift repository; declared in Nightshift's
`docs/FOUR_OFFICE_PILOT_01.md`, itself the pilot's broker-authored governed
effect) both ran on this runtime without code changes. Not operator-ready or
production-hardened; the trust-model premises below still hold the load.

The compared prior Rust implementation, `transition-kernel`, is a **research
cousin, not a predecessor**: the Task 14 comparison
([`old-rust-comparison.md`](docs/governed-runtime/old-rust-comparison.md))
concluded "complementary organs, not rivals" and imported nothing.

**Read the trust model before relying on anything here.**
[`docs/governed-runtime/trust-model.md`](docs/governed-runtime/trust-model.md) states what
is enforced and what is assumed. Three assumptions are load-bearing and are premises rather
than guarantees: exclusive broker custody of the governed target ref, same-UID trust of the
labor provider and broker binary, and monotone clock readings. Several claims a reader
might expect to be enforced are deliberately written down there as premises instead.

## Where to start

| | |
|---|---|
| What it is and what it claims | [`greenfield-result.md`](docs/governed-runtime/greenfield-result.md) |
| The thirty invariants and their provenance | [`invariants-v0.md`](docs/governed-runtime/invariants-v0.md) |
| What is enforced vs. assumed | [`trust-model.md`](docs/governed-runtime/trust-model.md) |
| Current conformance classification | [`conformance-v0-second-pass.md`](docs/governed-runtime/conformance-v0-second-pass.md) |
| What it does not do | [`greenfield-known-gaps.md`](docs/governed-runtime/greenfield-known-gaps.md) · [`non-goals.md`](docs/governed-runtime/non-goals.md) |
| Test coverage | [`greenfield-test-matrix.md`](docs/governed-runtime/greenfield-test-matrix.md) |
| Install from source and bootstrap clean state | [`source-install-and-bootstrap.md`](docs/governed-runtime/source-install-and-bootstrap.md) |
| First governed execution (pilot) | [`pilot-01.md`](docs/pilot-01.md) · [`pilot-01-followup.md`](docs/pilot-01-followup.md) |
| The supported evidence/read surface | [`attempt-dossier.md`](docs/governed-runtime/attempt-dossier.md) |
| Repository identity and ref-continuity handoff | [`repository-identity-and-ref-continuity.md`](docs/governed-runtime/repository-identity-and-ref-continuity.md) |
| What effects are admissible | [`effect-classes.md`](docs/governed-runtime/effect-classes.md) |
| What each outcome means and what to do next | [`operator-runbook.md`](docs/governed-runtime/operator-runbook.md) |
| First upstream-authorized governed change | [`vertical-01.md`](docs/vertical-01.md) |
| How upstream authorization becomes local standing | [`upstream-authorization.md`](docs/governed-runtime/upstream-authorization.md) |
| Docket-local execution permission and the alpha.6-qualified use | [`local-execution-standing.md`](docs/governed-runtime/local-execution-standing.md) · [alpha.6 walkthrough](https://unpingable.com/constellation/releases/0.1.0-alpha.6/guide.html) |

Documents cite an external "normative packet" as their requirements source. That packet is
held privately and is not part of this repository; the citations are to an external source,
not to missing files.

## Install from source

Docket currently has a source installation path, not a published-package promise. From a
clean checkout, build both required executables and inspect the operator surface:

```bash
cargo build --locked --workspace
./target/debug/docket --help
test -x ./target/debug/gwr-git-broker
```

The `docket` and `gwr-git-broker` executables must remain siblings, unless
`GWR_BROKER_BIN` explicitly names the broker. Required build and runtime dependencies,
an optional `cargo install --path` flow, clean state creation, provider configuration, and
supported versus unsupported invocation paths are recorded in
[`source-install-and-bootstrap.md`](docs/governed-runtime/source-install-and-bootstrap.md).

The canonical AG governed-loop custody record has one narrow read-only
projection for the local operator inspector:

```bash
docket governed-loop inspect --state /absolute/state --issuance sha256:...
```

It opens the existing custody database read-only and emits
`docket.governed-loop.inspection/v1`, including the exact authenticated AG
issuance, issuer/key identity, custody, executor binding, and known or
indeterminate outcome. It invokes no standing resolver or executor and does
not reconcile or alter custody.

### Governed-executor transport ownership

Docket owns the generic, versioned dispatch/outcome/reconcile transport law.
Its independent specification, closed V1 schemas, and conformance vectors are
[`executor-transport-v1.md`](docs/governed-runtime/executor-transport-v1.md)
and [`conformance/executor-transport-v1/`](conformance/executor-transport-v1/).
Executors retain ownership of their sealed plans, mechanics, journals, and
receipt formats; AG retains governed occurrence and authorization semantics.
Consumers intentionally keep independent implementations rather than sharing
Docket runtime code.

## Workspace

- `crates/gwr-core` — pure deterministic types and transition rules. No I/O.
- `crates/gwr-runtime` — use-case coordination and neutral ports.
- `crates/gwr-local` — SQLite, filesystem artifacts, provider adapters, Git broker,
  observations, CLI, clocks, identity generation.

## Verification

Four gates, all required:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

Pass/fail is decided by exit codes, never by reading the tail of the output.

The release run is not redundant: a defect was shipped once whose behaviour differed
between build profiles — a `debug_assert!` panicked in debug on operator-supplied input
while release silently accepted it. Both suites must be green.

At the freeze this was 125 tests, identical in both profiles.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Vulnerability
reports should not be filed as public issues.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Attribution and authorship: [PROVENANCE.md](PROVENANCE.md).
