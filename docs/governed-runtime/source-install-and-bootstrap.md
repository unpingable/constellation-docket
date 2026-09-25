# Source installation and clean-state bootstrap

This is the supported way to obtain and start the local Docket runtime from a clean source
checkout. It is an operational guide, not a package release or a change to Docket's
authority, repository-identity, settlement, or reliance semantics.

## Prerequisites

The operator environment needs:

- the Rust toolchain pinned in `rust-toolchain.toml` (1.94.0, with clippy and rustfmt);
  run all repository gates before relying on a build;
- network access to the configured Cargo registry, or an already populated Cargo cache,
  because dependencies are locked but not vendored;
- a native C compiler/linker usable by Cargo's `ring` build;
- `git` on `PATH` at runtime;
- a writable absolute state-directory location and a writable system temporary directory;
  and
- any executable named by an observation plan, with its own runtime dependencies, on
  `PATH` when `docket observe` runs it in a detached worktree.

`rusqlite` is built with its `bundled` feature. A separately installed system SQLite
library or `sqlite3` CLI is not required.

No Git user configuration is needed for broker-authored commits: the broker supplies its
fixed author and committer identity. The deployment still must arrange the trust-model
premises described in [the trust model](trust-model.md), including exclusive custody when
relying on a recovery verdict that asserts non-occurrence.

## Build and invoke from the checkout

From the repository root:

```bash
cargo build --locked --workspace
test -x ./target/debug/docket
test -x ./target/debug/gwr-git-broker
./target/debug/docket --help
```

`cargo build --workspace` builds both operator executables. Keep them together:
`docket` resolves `gwr-git-broker` as a sibling of its own executable by default.

For an installation into an explicit writable prefix, Cargo can install both binaries
directly from this checkout:

```bash
docket_install_root=/absolute/writable/docket-install
cargo install --locked --path crates/gwr-local --root "$docket_install_root"
test -x "$docket_install_root/bin/docket"
test -x "$docket_install_root/bin/gwr-git-broker"
"$docket_install_root/bin/docket" --help
```

Put that `bin` directory on the operator's `PATH` if commands will use the short
`docket` spelling. This repository does not promise that `cargo install gwr-local` from a
registry, a downloaded release archive, or a system package manager will work; none is a
published installation surface here.

If the broker cannot remain beside `docket`, name the exact executable explicitly:

```bash
export GWR_BROKER_BIN=/absolute/path/to/gwr-git-broker
```

Copying or installing only `docket` without its broker is not a supported dispatch setup.
`GWR_BROKER_BIN` is an operational executable locator; it does not confer authority.

## Bootstrap an empty state directory

There is no implicit default state and no identity cache. Every stateful command takes an
explicit `--state <directory>`. The first such command creates the directory, applies the
SQLite schema migrations, and creates state below it as needed:

```text
state.sqlite
artifacts/
journals/
provenance/
standing.key
```

Start with an absent or empty writable directory and an existing governed Git checkout:

```bash
docket_state_dir=/absolute/writable/docket-state
governed_repo_dir=/absolute/path/to/governed-repository

docket repository register \
  --state "$docket_state_dir" \
  --repo "$governed_repo_dir"
```

The command prints a newly minted opaque `repo-…` identifier. Retain that exact value and
pass it, together with the current absolute path locator, when creating work:

```bash
docket_repository_id=repo-00000000000000000000000000000000

docket repository show \
  --state "$docket_state_dir" \
  --repository-id "$docket_repository_id" \
  --json

docket request create \
  --state "$docket_state_dir" \
  --repository-id "$docket_repository_id" \
  --repo "$governed_repo_dir" \
  --target-ref refs/gwr/target \
  --goal "apply the reviewed change"
```

Replace the example identifier with the value printed by `repository register`; the
all-zero spelling is illustrative, not a reserved or discoverable identity. Do not derive
the value from the path, remote, commit, tree, or checkout. The complete relocation and
legacy migration procedure is in
[repository identity and ref continuity](repository-identity-and-ref-continuity.md).

## Preparation providers and writable temporary storage

The checked-in provider surfaces are:

- `--provider fake --fake-patch <file>` — ingest the exact supplied patch through the
  scripted provider. This is suitable for reproducible specimens and test harnesses; it
  does not bypass candidate admission, ratification, reservation, or dispatch.
- `--provider codex` — run the optional Codex provider. `codex` must be on `PATH`, or
  `GWR_CODEX_BIN` must name its executable. Its own installation, authentication,
  configuration, and network access are external operator responsibilities.

Preparation creates a disposable per-run workspace under the system temporary directory.
Set `GWR_WORKSPACE_ROOT` to an explicit writable parent if the system temporary location is
unsuitable:

```bash
export GWR_WORKSPACE_ROOT=/absolute/writable/docket-workspaces
export GWR_CODEX_BIN=/absolute/path/to/codex
```

`GWR_CODEX_BIN` is needed only for the Codex provider. Neither environment variable
supplies repository identity, state, standing, or authority.

## Supported and unsupported invocation paths

Supported:

- build or install both binaries from the same checked-out, locked source tree;
- use an explicit writable state directory;
- register an opaque repository identity once and separately supply an absolute current
  path locator;
- relocate that registration explicitly before creating work at a new path;
- use the documented fake or optional Codex provider;
- inspect canonical evidence with `docket list`, `docket show`, and `docket journal`; and
- export a committed attempt's complete operation with `docket continuity subject`.

Unsupported:

- assuming an unpublished registry package, release archive, or OS package exists;
- copying only `docket` and silently finding a broker elsewhere on `PATH`;
- treating a relative path, current working directory, remote URL, commit, tree, or
  historical locator as repository identity;
- importing a developer state directory, identity cache, standing key, artifact store, or
  shell alias as bootstrap;
- treating `continuity subject` as a Git continuity check—it exports Docket's recorded
  operation and does not inspect Git or execute Continuity; or
- expecting relocation to rewrite an already admitted attempt's stored execution locator.

The operator outcome meanings and next actions are in the
[operator runbook](operator-runbook.md). The repository's required formatting, lint,
debug-test, and release-test commands are in the root [README](../../README.md#verification).
