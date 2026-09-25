# Demo: an effect whose outcome is unknown

An agent asks for a refund at a payment provider. The request goes out, and the
reply never comes back. The agent's command exits 0, and the agent reports
"Done." Docket, the component that keeps custody of each attempt, records the
attempt as **indeterminate**: not success, not failure. It does not retry,
because a retry could refund twice. Later, a separate observer asks the
provider what is actually in its ledger, and only then does Docket settle the
attempt.

The demo runs this twice with the same agent and the same "Done." In run A
the provider's reply is lost, so the refund really happened and Docket settles
**success**. In run B the request itself is lost, so the refund never happened,
and after the provider's deadline has passed Docket settles **failure**. The
agent's message cannot tell these cases apart. The provider's records can.

## Run it

On Debian 12 (other Linux distributions work with equivalent packages):

```sh
sudo apt-get install -y git curl gcc libc6-dev python3 openssl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"
git clone -b campaign/public-demo-20260925 https://github.com/unpingable/constellation-docket.git
cd constellation-docket
./examples/indeterminate-effect/run.sh
```

`run.sh` builds the two Docket binaries from this checkout with the pinned Rust
toolchain (`rust-toolchain.toml`, 1.94.0; rustup fetches it on first use), runs
the demo, then runs the independent check. On a fresh 4-core Debian 12 VM the
whole path took about three minutes: 80 s for the packages, 12 s for rustup,
the toolchain and the crates, 54 s for the build, and 10 s for the demo, most of
which is waiting for run B's deadline. Network access is needed only for the
packages, the toolchain, the clone and the crates.io dependencies. The build
and the demo also run with the network cut off; the demo uses only 127.0.0.1.

Everything is written to `examples/indeterminate-effect/out/<time>/`:
`transcript.txt` (what you saw), `check.txt`, and the raw records listed below.

## Who does what

| Part | Program | Owns |
|---|---|---|
| Agent (stand-in) | `bin/agent` | its completion claim, `agent-claim.json` |
| Authorization (stand-in for constellation-ag) | `authority_standin.py` | the signed work order, `authorization.json` |
| Docket | `docket` built from this repository | the attempt, its disposition and settlement, `docket-state/` |
| Worker | `bin/refund-executor` | sending the request once, its journal, `executor-journal/` |
| Network | `bin/flaky-link` | the one injected fault, `network.log` |
| Payment provider | `bin/provider` | whether the refund exists, `provider/ledger.jsonl` |
| Observer | `bin/observe` | what the provider said when asked, `observations/` |

The agent is a script, not a model: it runs a command and reports "Done." when
the command exits 0. That is the habit this demo is about. The exit code says
the command finished. It does not say the refund exists.

## Why the final answer is independent of the agent

- **The fault is chosen in one place.** Only `flaky-link` knows whether the
  request or the reply is dropped. The worker, the observer and Docket never
  read its log, and neither does the check's verdict.
- **The worker never guesses.** `refund-executor` reports success only if it
  holds the provider's reply. With no reply it reports "indeterminate", with a
  digest of what it does know (the request went out; no answer came back).
- **Docket's first answer is indeterminate.** It records that evidence and
  holds the attempt open. Re-sending the same authorization returns the same
  attempt, and nothing is sent again.
- **The later evidence comes from the provider, not the worker.** Docket
  resolves an indeterminate attempt only through the executor's `reconcile`
  operation, which by contract must not repeat the effect
  ([executor transport](../../docs/governed-runtime/executor-transport-v1.md)).
  Here, `reconcile` does not read the worker's journal. It runs `bin/observe`, a
  separate program that asks the provider's read-only lookup endpoint
  directly, not through the faulty link. The observer's document, which quotes
  the provider's answer verbatim, becomes Docket's settlement receipt.
- **One fixed rule turns the provider's answer into an outcome.** If the
  provider has the exact request committed, the outcome is success. If the
  provider lacks it and its deadline has passed, the outcome is failure, since
  the provider refuses the request after that time and the request id binds the
  deadline. In every other case the attempt stays indeterminate. Run B asks once
  too early and stays indeterminate.
- **The agent's claim is never an input.** Nothing reads `agent-claim.json`
  except the narration and the check. The same claim leads to opposite outcomes.

## Check it yourself

`check.py` shares no code with the demo. From the retained files it:

- verifies the authorization's signature and recomputes its identity;
- recomputes Docket's attempt and marker ids, and every reconciliation and
  settlement digest;
- re-derives what really happened from the provider's own ledger and access
  log, and applies the rule above;
- compares the result with Docket's final record, the observer's documents and
  the agent's claim;
- with `--docket`, re-reads Docket's store (read-only) and requires it to equal
  the retained copies.

```sh
python3 examples/indeterminate-effect/check.py examples/indeterminate-effect/out/<time> \
  --docket target/release/docket
```

Edit a retained record, such as the provider ledger or Docket's final outcome,
and the check fails.

## Limits

- **Stand-in authorization.** The authorizing service (constellation-ag) is not
  running. `authority_standin.py` signs with AG's issuance rule and first proves
  it by reproducing AG's published test vector
  (`conformance/ag-governed-loop-issuance/v2-vectors.json`) byte for byte. Its
  key is fresh and thrown away after the run.
- **Docket trusts the executor's reconcile.** Docket binds the executor's
  program bytes and plan. The observer's path is in the executor's
  configuration, which Docket does not bind. The independence argument above
  covers this composition. It is not a general Docket guarantee.
- **The executor's own "success" is believed.** Had the worker received a
  reply, Docket would have settled at once from the worker's receipt. The demo
  shows the case where the worker cannot know.
- **The provider, the network fault and the agent are small local stand-ins.**
  Everything runs on one host, under one clock and one user account.
- **This is the demo branch, not a release.** It builds Docket from source at
  this commit (the `alpha-exit-packaging` line, `3093def` plus this
  directory). It is not the packaged Docket 0.1.0 artifact.
