# Provider-contract executable publication repair

Status: qualified predecessor-witness repair.

This repair is independent of the VM-guest proposition. It changes no Stage-0
code, C1/C2 law, Docket transport, governed-loop semantics, authority, or
provider result classification.

## Custody

Diagnosis began on branch `campaign/vm-guest-stage0-host-sim` at C2 revision
`c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`, with the already-qualified
Stage-0 worktree intentionally uncommitted. The Stage-0, C1, and C2 artifact
hashes were verified before and after this repair and remained identical.

Crow has no `TMPDIR`, `TMP`, or `TEMP` override. `/tmp` is on the local
ext4 root filesystem `/dev/mapper/vgubuntu-root`, mounted read/write with
`relatime`; it is not NFS, overlayfs, or tmpfs. Qualification used Linux
6.5.0-44-generic on x86-64.

## ETXTBSY diagnosis

The original test helper used `std::fs::write` to create a different
`fake-codex` shell script in each test's PID-qualified directory, chmodded it
0755, and immediately supplied that path to `Command::spawn`.

Baseline stress results were:

```text
50 isolated suite runs, default test threads: 22 pass, 28 fail
50 isolated suite runs, --test-threads=1: 50 pass, 0 fail
```

Failures moved among the candidate, nonzero-exit, and no-change specimens.
Paths and inodes were distinct. No fixture-name collision or surviving
`fake-codex` process was found.

Syscall tracing showed each creating thread opening its script
`O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC` and explicitly closing that descriptor.
The same multithreaded process concurrently used
`clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND)` to spawn other commands.
Ten traced parallel runs passed because tracing widened/serialized the critical
timing.

The cause is cross-fork descriptor inheritance, not a missing Rust `drop`.
A child cloned while another thread has a script open can transiently inherit
that writable descriptor. `O_CLOEXEC` closes it only when the child executes.
A concurrent exec of the same inode can therefore observe an outstanding
writer and return `ETXTBSY`, even though the creating thread already closed
its copy.

Writing a temporary pathname and atomically renaming it would not by itself
remove this race: an already-cloned child would still hold a writable
descriptor to the same inode after rename.

## Structural fixture repair

The fake provider is now one immutable executable fixture committed as
`tests/fixtures/provider-contract-fake-codex`. Git publishes it before the
multithreaded test process starts. The fixture selects its fixed behavior only
from the existing disposable workspace pathname. Tests perform no runtime
write, chmod, rename, sleep, or retry on an executable pathname.

This is a harness-only publication change. The candidate, failure, no-change,
hang, and workspace-isolation semantics remain the same.

## Timeout descendant diagnosis and repair

A separate trace proved the hang specimen did leak a live descendant:

- fake shell PID 494300;
- child `sleep 30` PID 494301;
- provider sent SIGKILL only to PID 494300;
- the sleep remained until its 30-second completion.

This is a genuine local provider timeout-containment defect, not a Stage-0
defect. The provider now launches the bounded labor process in a new process
group and, on timeout, invokes the fixed trusted-host utility
`/bin/kill -KILL -- -GROUP` before the existing direct-child kill/wait
fallback. No unsafe code or Cargo dependency was added.

The immutable hang fixture deliberately forks a sleep, records its PID, and
waits. The test requires the descendant to become absent or terminal
zombie/dead within one second. The bounded one-millisecond observation poll is
only for asynchronous SIGKILL delivery/reaping; no retry was added to
executable publication or spawn.

The new host-mechanics premise is that qualified Crow provides the measured
standard `/bin/kill` process-group operation. It does not enter Docket,
Stage-0, or guest semantics.

## Parallel local-ID collision found by the full gate

The exact repair-only commit's full-suite gate exposed a second predecessor
defect. A serial `read_surface` suite passed, while repeated default-parallel
runs failed at different witnesses. Preserving and tracing a failed specimen
proved that two fixtures had received the identical dispatch ID
`301ef90d3658ffd4ca5d8e7d4d56f5df`. Both therefore selected the same global
`/tmp/gwr-index-<dispatch>` path.

One broker's journal stopped at `received -> verified`; its `git read-tree`
exited 128 on the shared index while the other fixture used it. The two exact
envelope and journal paths were:

- `/tmp/gwr-reads-list-qualified-661349/journals/301ef90d3658ffd4ca5d8e7d4d56f5df.*`
- `/tmp/gwr-reads-secrets-661349/journals/301ef90d3658ffd4ca5d8e7d4d56f5df.*`

`HashChainIds::new` had described its seed as process-unique but bound only
the current time and PID. Concurrent constructors in one process could observe
the same time and therefore mint identical chains. This was a genuine
`gwr-local` mechanics defect, not a Stage-0 or transport result.

The seed transcript now also binds a process-local monotonic atomic instance
coordinate. A 64-thread barrier test proves distinct first identities from
concurrent sources. No wire shape, authority, outcome, or layering changed.

## Qualification

Exact results:

```text
cargo test -p gwr-local --test provider_contract_codex --quiet
PASS: 7 passed

100 repeated default-parallel provider-contract suite runs
PASS: 100 passed, 0 failed

cargo test -p gwr-local --test read_surface --quiet
PASS: 9 passed

100 repeated default-parallel read-surface suite runs
PASS: 100 passed, 0 failed

cargo clippy -p gwr-local --test provider_contract_codex -- -D warnings
PASS

cargo test --workspace --quiet
PASS: 302 passed

cargo test --workspace --release --quiet
PASS: 302 passed

cargo test -p gwr-local stage0_guest --lib
PASS: 15 passed

cargo test -p gwr-local --test stage0_guest_process
PASS: 8 passed

cargo test -p gwr-local governed_loop
PASS: 17 passed

cargo test -p gwr-local executor_transport
PASS: original Docket and independent Stage-0 C1 runners
```

Formatting and patch hygiene passed. Frozen identities remained:

| Artifact | SHA-256 |
| --- | --- |
| Stage-0 qualification | `1fad49860af22ee258f6fec6c0f0a384eac19e38131ee9fbe28262a11d191e45` |
| Stage-0 protocol | `d5b352ed535b5d7ed6a498e6b3e8659e43ba216ffa88afba58f8b4acc8b5b801` |
| Stage-0 hostile corpus | `b5fdd280c77ddb660f8bdcfee5b50111685d65c7b3122de8b83e58d2df11ff85` |
| C2 qualification | `62573c10fb033637a27e47f4374d90e2bff3e2bf6c95be11e4eb1a91245eb695` |
| C1 specification | `b54f8db4d89c7e422733757f7a69b7fcc7420ce225f782f493c703c8e39e41a1` |
| C1 dispatch schema | `704c474e93e7bce83ea51fda38b8446ed1be95cd658db14c5bd5cb5c4a28fadd` |
| C1 outcome schema | `3851b2b43097936a3494ac6a43e26a2b5cb040e55847c867f05b62516ec0ca3f` |
| C1 corpus | `3e58081f7cc36ecfad44ee9860c77ec5784b34c91e7c707d126f00ef778cf687` |

Classification: `QUALIFICATION-WITNESS-REPAIRED`.
