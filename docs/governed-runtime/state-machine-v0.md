# State Machine v0 — Exact Attempt Lifecycle

Terminology per `architecture-v0.md` and the packet glossary. Invariant numbers refer to
`invariants-v0.md`.

This state machine describes the Git-ref workflow, including `docket recover resolve`
and its distinct recovery standing. The [governed-loop reconciliation command](operator-runbook.md#reconcile-an-existing-governed-loop-attempt)
uses an existing attempt's custody and can record settlement without recovery standing.

## Execution states

An attempt's execution state is exactly one of:

```text
Prepared
Ratified
Reserved
Dispatching
Committed
DispatchRefused
Indeterminate
CommittedViaRecovery
ProvenNotCommitted
```

Legal transitions — and no others:

```text
Prepared      -> Ratified            (StandingToRatificationV1)
Ratified      -> Reserved            (exclusive one-use reservation)
Reserved      -> Dispatching         (ReservationToDispatchV1; mints the one DispatchId)
Dispatching   -> Committed           (broker acknowledges atomic ref update)
Dispatching   -> DispatchRefused     (broker definitively refuses; no ref update occurred)
Dispatching   -> Indeterminate       (acknowledgement lost / broker death / unknown)
Indeterminate -> CommittedViaRecovery (RecoveryStandingToResolutionV1)
Indeterminate -> ProvenNotCommitted   (RecoveryStandingToResolutionV1)
```

Transitions are monotone (invariant 27): no state is ever re-entered, no transition runs
backwards, and terminal states (`Committed`, `DispatchRefused`, `CommittedViaRecovery`,
`ProvenNotCommitted`) are terminal forever. `DispatchRefused` and `ProvenNotCommitted`
remain distinct states permanently (invariant 28): one records a definite refusal before
any effect; the other records a recovery-established fact about an effect whose outcome
was once unknown.

## Reachability rules

- Dispatch is unreachable before admission, ratification, **and** reservation. There is no
  path to `Dispatching` that skips any of `Prepared`, `Ratified`, `Reserved`.
- Exactly one `DispatchId` may ever be persisted per attempt (invariant 3). Presenting the
  same `DispatchId` again inspects the existing dispatch; it never repeats the effect
  (invariant 4). A different `DispatchId` for the same attempt is refused (invariant 5).
- `Indeterminate` is a positive, durable fact — it survives restart, and nothing about
  elapsed time, retry cost, or likelihood moves an attempt out of it. The only exits are
  through exact recovery evidence **plus** separately held recovery standing (invariants
  6–11). Unresolved or conflicting evidence remains `Indeterminate`.
- No crash path retries or guesses. A crash observed in any pre-dispatch state leaves the
  attempt in that state; a crash inside `Dispatching` resolves only to what the broker
  journal and acknowledgement establish, else `Indeterminate`.

## Associated records (never state variants)

These attach to an attempt without changing the execution-state enum:

- **Observation** — a recorded execution of an exact command against an exact result
  state: argv, working-directory identity, result commit, environment description, exit
  status, output digests. Observation failure cannot rewrite an effect commitment
  (invariant 18): a failing observation against `Committed` means the effect committed and
  the command failed.
- **Reliance decision** — consumer-indexed and claim-indexed admission or refusal,
  produced only by a named bridge. Never mutates or broadens its source (invariant 22).
- **Reconciliation** — the closing account of what remains owed.
- **Residual obligation** — something still owed after the mechanical transition
  succeeded. `HumanReviewBeforeMerge` is the v0 instance; it remains visible after
  `Committed` and after a passing observation (invariant 29), and nothing in the low-level
  path discharges it.
- **Recovery fact** — evidence binding a specific attempt and dispatch to an observable
  state of the world. Storing one changes nothing (invariant 10); only
  `RecoveryStandingToResolutionV1` applies it.

## Scenario walkthroughs

Columns: prior state → record/refusal produced → resulting state → standing consumed →
reservation consumed → uncertainty exists → retry allowed.

| # | Scenario | Prior state | Record / refusal produced | Resulting state | Standing consumed | Reservation consumed | Uncertainty | Retry allowed |
|---|---|---|---|---|---|---|---|---|
| 1 | Provider dies before producing a candidate | Preparation run active; no attempt exists | `PreparationFailed` record (provider death is provenance, not an effect outcome) | Work request open; no attempt | no | none exists | no — no effect was ever attempted | yes: a new `PreparationRunId` |
| 2 | Candidate arrives after expiry | Preparation run expired; no attempt | Admission refusal `CandidateExpired`; candidate bytes retained as provenance | No attempt minted | no | none exists | no | yes: new preparation under operator decision; expired run does not revive (inv. 25) |
| 3 | Provider A replaced by provider B | Preparation run A ended | Run-ended record for A; new run record for B | New `PreparationRunId`; core lifecycle untouched | no | none exists | no | n/a — replacement is not a retry of any attempt |
| 4 | Ratification names wrong basis or prepared-attempt digest | `Prepared` | Refusal `RatificationDigestMismatch` (or `RatificationBasisMismatch`) | `Prepared`, unchanged | **no** — malformed requests consume nothing | none exists | no | yes: a correct ratification of the same attempt may follow |
| 5 | Standing is expired | `Prepared` | Refusal `StandingExpired` | `Prepared`, unchanged | no — expired standing cannot be consumed, and later window extension does not un-expire it (inv. 25) | none exists | no | yes, with different valid standing |
| 6 | Standing already consumed | `Prepared` | Refusal `StandingAlreadyUsed` | `Prepared`, unchanged | no (nothing left to consume; inv. 12) | none exists | no | yes, with different valid standing |
| 7 | Reservation conflicts with an active reservation | `Ratified` | Refusal `ReservationConflict` — conflict produces refusal, not waiting | `Ratified`, unchanged | already consumed at ratification (unchanged) | no | no | yes: reserve again after the conflicting reservation expires or is consumed |
| 8 | Reservation is replayed | `Reserved` (use already spent) or later | Refusal `ReservationAlreadyUsed` | Unchanged | unchanged | no second consumption (inv. 13) | no | no — not under this reservation |
| 9 | Target ref moves before dispatch | `Reserved` → `Dispatching` | Broker refusal `BasisMoved`; `DispatchRefused` outcome record | `DispatchRefused` (terminal) | consumed (at ratification) | **yes** — the dispatch spent the one use | no — refusal is definite; no ref update occurred | not under this `AttemptId` (inv. 2); a new attempt against the new basis may be prepared |
| 10 | Broker dies before applying the effect | `Dispatching` | Journal shows no ref-update phase; no acknowledgement; `Indeterminate` outcome record | `Indeterminate` (durable, survives restart) | consumed | consumed | **yes** | no automatic retry (inv. 7); exit only via recovery |
| 11 | Effect applies but acknowledgement is lost | `Dispatching` | No acknowledgement; `Indeterminate` outcome record; later: recovery fact (observed ref = expected result commit) | `Indeterminate`; after separately authorized resolution: `CommittedViaRecovery` | consumed; resolution consumes **recovery** standing | consumed | yes, until resolution | no retry ever; resolution is not a retry |
| 12 | Effect applies but observation fails | `Committed` | Observation record with non-zero exit status | `Committed`, unchanged — observation cannot rewrite commitment (inv. 18) | consumed | consumed | no (commitment is definite; only the command failed) | new observations may be recorded; the effect is never re-run |
| 13 | Observation runs against the wrong result commit | `Committed` | Refusal `ObservationScopeMismatch`; the record is retained but supports no claim | `Committed`, unchanged | consumed | consumed | no | a correctly-scoped observation may be run |
| 14 | Recovery fact names another attempt | `Indeterminate` | Refusal `RecoveryAttemptMismatch`; fact stored as inert record | `Indeterminate`, unchanged (inv. 9) | recovery standing **not** consumed | consumed (historically) | yes, still | resolution may be attempted with a correctly-bound fact |
| 15 | Recovery fact authentic, actor lacks recovery standing | `Indeterminate` | Refusal `RecoveryStandingInsufficient` (inv. 11) | `Indeterminate`, unchanged | no | consumed (historically) | yes, still | resolution may be attempted by an actor with standing |
| 16 | Refusal used by an unsafe downstream consumer | Any; a refusal record exists | Reliance refusal `ClaimNotAdmissible` — a narrow refusal is not its own negation (N5) | Unchanged; source refusal not mutated (inv. 22) | n/a | n/a | unchanged | n/a |
| 17 | Observation receipt used outside its scope | `Committed` with observation | Reliance refusal `ObservationOutOfScope` | Unchanged | n/a | n/a | unchanged | n/a |
| 18 | Bridge version unsupported | Any bridge input | First-class reliance refusal `BridgeVersionUnsupported` — no fallback, no pass-through (inv. 30, N3) | Unchanged | no | no | unchanged | the consumer may present a supported version |

## Confirmations

Checked against this machine as specified:

- Dispatch is unreachable before admission, ratification, and reservation — the only path
  to `Dispatching` traverses `Prepared → Ratified → Reserved`.
- No crash path retries or guesses — scenarios 9–11 produce refusal or indeterminacy,
  never a minted success or failure (invariant 6).
- Indeterminacy exits only through exact recovery evidence plus recovery standing —
  scenarios 14 and 15 show each half alone refusing.
- Observation failure cannot rewrite an effect commitment — scenario 12.
- No bridge transports correctness, merge safety, completion, or obligation discharge —
  see `bridge-specifications-v0.md`, "information explicitly not transported" for all four
  bridges.
