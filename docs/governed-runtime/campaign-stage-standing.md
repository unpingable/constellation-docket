# Campaign-Stage Standing (S-2)

Status: implemented on branch `campaign/stage-standing`. This document is the law of the
campaign-stage standing domain: what it is, what it premises, what it refuses, and what it
never claims. It is a distinct standing domain alongside the effect-standing domain
(`git-ref-update:v1`); neither document nor code of that domain is altered by this one.

## What this domain is

An orchestration office (AG-NG) runs campaigns in stages. A stage needs authority to run
exactly once, against an exact basis, inside an exact scope, before an exact expiry. This
domain issues that authority as a **campaign-stage standing instrument** and records its
consumption, its outcome, and the adjudication of its review.

The vocabulary, in `gwr_core::campaign`:

- **Stage classes** with standing: `operator_stage`, `reviewer_stage`,
  `records_repair_stage`, `existing_source_scope_repair_stage`, `final_review_stage`.
- **Stage classes without standing, ever**: `new_source_scope`, `architecture`,
  `authority`, `basis`, `candidate`, `freeze`, `qualification`, `certificate`, `registry`,
  `deployment`. Requesting one refuses with
  `CampaignRefusal::StageClassNeverAdmitted { class }` — a typed refusal that names the
  class, at the input boundary, before anything is created.
- **Worker roles**: `operator`, `reviewer`, `repair`. The stage class fixes the role.
- **Effect classes**: `workspace_mutation` (operator), `review_read_only` (reviewer and
  final review), `records_only` (records repair), `existing_source_scope` (source-scope
  repair). The stage class fixes the effect class; proposing anything else is
  effect-class widening and refuses at proposal validation.

## Digests and dual identity

Every digest is over an explicit versioned transcript with a domain tag:

- Proposal: `gwr:campaign-stage-proposal:v1`
- Standing: `gwr:campaign-stage-standing:v1`
- Consumption: `gwr:campaign-stage-consumption:v1`
- Adjudication: `gwr:campaign-stage-adjudication:v1`

The proposal binds, in a fixed transcript order: the upstream digest, campaign and stage
identity, stage class, role, effect class, predecessor stage or root authorization
identity, every repository pin (locator, commit, tree) in order, every allowed path in
order, evidence contract, handoff schema identity, expiry, nonce, isolated worktree
identity, review requirement, nonclaims, repair basis when present, and the proposal
timestamp. Changing any field, label, order, or domain tag is a version bump.

**Dual identity.** AG-NG emits stage proposals carrying a digest under its own domain
(`ag.campaign.stage-proposal/v1`). Admission binds that digest verbatim as an opaque
upstream identity: it is recorded as a field of the proposal and of the standing, and is
never recomputed from a different canonicalization. Docket's own proposal digest is
computed independently over Docket's own transcript. Neither is derived from the other.

The issued standing digest is the value AG-NG effect/runtime receipts and sidecar
(campaign-driver) execution envelopes reference. Consumption records reference the
standing digest at burn time and the consuming receipt digest once it is known; the
receipt digest is recorded verbatim (the same dual-identity pattern) and is immutable
once recorded.

Persistence reads of proposals, standings, and adjudications recompute the content
address from the persisted fields; a record whose fields were altered after the fact
reads as typed corruption, not as the original record. Consumption rows are the mutable
exception by design: the burn row is primary-keyed on the standing and its
`effect_completed`/`receipt` columns are filled in as the outcome becomes known — the
receipt once, immutably (`ImmutableRebind` on any change) — so a consumption digest is
not recomputed on read.

## The instruments

**Proposal** (`CampaignStageProposal`). Exact and content-addressed. Validation refuses,
typed: empty required fields; non-exact repository pins (commit and tree must be full
lowercase-hex object ids); zero repositories; zero or inadmissible paths
(repository-relative, non-traversing); role not the stage class's role; effect class not
the stage class's effect class; review classes without an isolated worktree identity;
repair classes without a repair basis (or non-repair classes with one); repair scope
class disagreeing with the repair stage class; repair basis without findings.

**Standing** (`CampaignStageStanding`). Issued only from an exact recorded proposal, by
`campaign admit`. It is role-bound, stage-bound, basis-bound (the proposal digest binds
every repository pin), path-bound, effect-bound, and expiring; its window is never wider
than its proposal's. Its fields are private. It is consumable exactly once. It is
non-transferable across roles: consumption presents an execution context (campaign,
stage, role, proposal digest) and every divergence refuses — campaign, stage, role, and
proposal substitution each have their own typed refusal. It cannot be broadened by worker
output: there is no API that edits a standing's scope, and expiry never revives. It is
not derivable from a historical receipt: issuance takes a proposal, never a receipt.
A standing for a stage that has since been re-proposed and re-admitted is historical;
presenting it as current refuses (`Superseded`).

**Consumption** (`CampaignStageConsumption`). The durable record of the one burn.
Consumption is burn-before-effect: `campaign consume` makes the record durable before
the caller runs any effect, and the effect happens outside this runtime (AG-NG or the
sidecar runs it). A replayed burn refuses.

**Adjudication** (`AdjudicationReceipt`). The durable receipt of a verdict over a review:
`continue`, `exact_repair`, or `refuse`, binding campaign, stage, the exact review
receipt adjudicated, the adjudicator, the findings, and the residual obligations.
Adjudicating a review receipt this runtime never recorded as the outcome of a consumed
standing for that campaign and stage refuses (`AdjudicationSubjectUnknown`).

**Residual obligations** (`ResidualStatement`, persisted in
`campaign_residual_obligation`). Recorded with their adjudication and preserved. There
is no discharge API, matching the runtime's reconciliation law.

## The crash-recovery law

The durable records classify a stage execution into exactly four states
(`ConsumptionState`):

1. **Effect not begun** — no burn is recorded. The stage may proceed.
2. **Standing consumed, effect outcome unresolved** — a burn exists with no completion
   marker. Ambiguous: the effect may or may not have run.
3. **Effect completed, receipt missing** — completion is marked but no consuming receipt
   is recorded. Ambiguous: the outcome exists but is not receipted.
4. **Effect completed and receipted** — terminal.

Only state 1 may (re-)execute. States 2 and 3 refuse re-execution
(`OutcomeUnresolved`, `ReceiptMissing`) — the runtime never guesses and re-runs an
ambiguous effect. State 4 refuses a duplicate effect (`EffectAlreadyReceipted`). The
service applies this classification before any consumption, so a crashed-and-restarted
runner that re-attempts a burn gets the refusal for the state it is actually in.

The burn itself is atomic. `burn_campaign_standing` runs the supersession check, the
existing-burn check, and the insert inside one immediate SQLite transaction, so exactly
one consumer — across threads, service instances, and processes sharing one file-backed
store — receives success, even when two consumers would write byte-identical records
(same standing, same context, same clock reading). Every other consumer receives the
exact classification of the durable winner's row, never a second success, and a failed
transaction leaves no row: standing is available exactly when no burn committed. The
law is carried by the database, not by any in-memory state or application-level lock.
Connections carry a bounded `busy_timeout` (`SQLITE_BUSY_TIMEOUT_MS`, five seconds):
ordinary short writer contention gets a bounded chance to resolve so the losing
consumer observes the committed burn and receives the typed classification; a lock held
past the budget returns a bounded store error, never a success. The timeout never
changes outcomes and is not a guarantee of eventual success.

## Reviewer standing

Reviewer and final-review stages issue standing that is role-bound to `reviewer`,
effect-bound to `review_read_only`, and bound to the exact committed review bases (the
repository pins) and an isolated worktree identity (required at proposal validation).
Read and test effects are permitted; every mutation — commit, push, tag, reset, rebase,
branch mutation, remote mutation — refuses with the operation named
(`ReviewerMutationForbidden`). Reviewer standing is one-use, like every standing here,
and an operator presenting it (or a reviewer presenting operator standing) refuses
(`RoleMismatch`).

## Repair standing

A repair proposal carries a repair basis: the original stage, the exact rejected review
receipt digest, the exact finding identifiers, the scope class, repair nonclaims, and a
new review requirement. Only the two repair stage classes can carry one, and each binds
its scope class: `records_repair_stage` ↔ `records_only`,
`existing_source_scope_repair_stage` ↔ `existing_source_scope`.

Admission (`campaign admit` for a repair proposal) requires the repair's predecessor
basis to cite the authorizing adjudication by exact digest. The cited adjudication must
be recorded, must belong to the same campaign, must adjudicate the original stage and
the cited rejected review receipt with verdict `exact_repair`, must carry an exactly
matching finding set, and must not be superseded by a newer adjudication of the same
receipt. The **original stage authority is then resolved through the immutable
consumed-standing chain**, never by stage name: the adjudicated review receipt
identifies the one durable burn of the original stage that carries it; that burn's
standing names the exact `proposal_digest` of the proposal that was actually executed;
that proposal is the original authority. If no burn carries the receipt
(`AdjudicationSubjectUnknown`), or more than one does
(`RepairOriginalStandingAmbiguous`), admission refuses rather than guess. A same-name
re-proposal — wider or narrower — is a record-only artifact and never re-bases the
anchor.

The **subset decision lives here, in Docket** — never in
the sidecar: every requested repository must be one of the original stage authority's
repositories, and every requested path must be one of its allowed paths. A repair may
narrow scope, never widen it. Any other verdict authorizes no repair; a repair citing a
receipt the adjudication does not cover refuses; substituted findings refuse; a widened
path or repository refuses by name. New-source-scope and architecture "repairs" are not
repairs: those classes are never admitted at all.

## The repair-authority artifact (P1)

A repair stage must not execute because a local file claims an adjudication happened.
`campaign export-repair-authority --standing <digest>` emits Docket's own read-only,
content-addressed projection of the durable authority: schema
`gwr:campaign-repair-authority:v1`, binding the campaign, the repair stage, role, stage
class, effect class, repair standing and proposal digests, the exact burn state of the
repair standing (absent before the burn, the burn digest after), the original stage,
the F1-chain anchors (original proposal, original standing, original consumption), the
rejected review receipt, the cited adjudication digest and verdict, the exact finding
IDs, the scope class, the repository pins, the allowed paths, expiry, nonce, and
nonclaims, plus the verifier-generation identity. Export re-verifies the F1 chain and
current law (adjudication and standing supersession, expiry, the subset check), so a
drifted or unlawful authority cannot be exported.

The canonical JSON is deterministic (fixed key order, two-space indent, LF, one
trailing newline). The typed Docket digest travels inside the artifact as
`docket_repair_authority`; the file's own identity is SHA-256 over the exact file
bytes in a `<file>.sha256` companion — the artifact never embeds its own file digest,
and no consumer re-canonicalizes. `campaign verify-repair-authority --bundle <file>
[--expect-standing <digest>]` parses strictly (unknown schema, missing or added
fields, wrong types, unknown tags, or a typed digest that does not recompute all
refuse), then re-derives the authority from the durable store and requires field-for-field
equality — including the exact burn state — under the verifier's clock, refusing with
the first differing field named. A stale, superseded, corrupted, or foreign artifact
never verifies. Both verbs are read-only. The sidecar's obligation is mechanical only:
pin the artifact bytes, verify the SHA-256, run this verifier, and compare the
returned references; Docket remains the semantic verifier.

## Relationship to the effect-standing domain

The effect-standing domain (`domain::standing`, act `git-ref-update:v1`) is unchanged:
no shared types, no shared tables, no shared refusals, no conversion between domains.
Campaign-stage standing does not ratify attempts, does not reserve refs, and is never
presented to the broker. Effect standing does not admit, consume, or adjudicate campaign
stages. A `git-ref-update:v1` effect inside a campaign stage, if one is ever wanted,
would require both instruments independently; this domain neither grants nor implies the
other.

## Premises

- **Runtime clock.** Expiry is judged against runtime clock readings; monotone time is
  an environment assumption (shared with the existing trust model).
- **The burn is durable before the effect.** The crash-recovery law is only as strong as
  the store's durability; a caller that runs the effect before `campaign consume`
  returns has stepped outside the governed path.
- **Upstream identity is opaque.** The upstream proposal digest is recorded verbatim;
  Docket does not verify AG-NG's canonicalization, only binds it.
- **Receipt digests are as-presented.** The consuming receipt digest recorded at outcome
  time is testimony about which receipt the effect produced; this runtime does not
  recompute the consumer's receipt.

## Nonclaims

- No claim that a stage's effect is correct, complete, or safe to merge; the domain
  governs authority and occurrence, not quality.
- No claim of OS-level confinement of the worker that holds standing (per the v0.1
  threat model).
- No automatic standing for any class outside the five admitted ones, and no path by
  which worker output broadens issued standing.
- No discharge of residual obligations, ever.
- No re-execution from an ambiguous crash state; the law is refuse, not guess.

## Invariants added by this domain

Stated here rather than in `invariants-v0.md`, which is the v0 audit-era table:

- **S2-1.** Campaign-stage standing is issued only from an exact, validated, recorded
  proposal. No standing from a receipt; no standing from worker output.
- **S2-2.** One consumption per standing, durable before the effect; the burn is one
  atomic transaction with exactly one winner under concurrency; replay refuses.
- **S2-3.** Consumption binds campaign, stage, role, and proposal digest; every
  substitution refuses.
- **S2-4.** Reviewer standing permits read/test only; every mutation refuses by name.
- **S2-5.** Repair admission cites the authorizing adjudication by exact digest and
  resolves the original stage authority through the consumed-standing chain (rejected
  review receipt → durable burn → consumed standing → proposal digest); the requested
  scope is a subset of that exact proposal's scope — decided in Docket, never anchored
  to a record-only re-proposal.
- **S2-6.** The never-admitted classes refuse by name at the input boundary.
- **S2-7.** Crash recovery has exactly four states; only effect-not-begun may proceed.
- **S2-8.** Residual obligations are recorded and preserved; there is no discharge.
- **S2-9.** A superseded standing is historical and refuses consumption.
- **S2-10.** This domain does not weaken, alter, or substitute for the effect-standing
  domain.

Each invariant has at least one test in `crates/gwr-local/tests/campaign_stage_standing.rs`,
`crates/gwr-local/tests/campaign_burn_concurrency.rs`,
`crates/gwr-local/tests/campaign_repair_authority.rs`, or the `gwr_core::campaign` unit
tests.
