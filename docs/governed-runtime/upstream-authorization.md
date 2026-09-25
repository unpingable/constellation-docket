# Upstream-authorized standing

Docket mints standing for an exact attempt in one of two ways. Both are visible in the
dossier's `authorization` block, and neither can masquerade as the other.

- **Local / manual** — `docket grant standing`. Operator authority, recorded as
  `source: local`. This is the bootstrap path and it remains supported.
- **Upstream-authorized** — `docket authz accept`. An upstream authorization office
  decided that this exact proposed work may receive authority and emitted an
  authenticated issuance; Docket verifies it and then mints its own standing, recorded
  as `source: upstream` with the issuance as its basis.

Grants written before source recording existed read as **unrecorded** — never as
either source.

## The two wire contracts

Both are Docket-owned and versioned; this repository is their authoritative home.

**`gwr:authz-request:v1`** — the authorization request, projected from the stored
prepared attempt by `docket authz request --attempt <id> --actor <name> [--json]`. It
carries the attempt identity and version, effect class, prepared-attempt transcript
digest, repository, target ref, basis, admitted paths, the actor proposed for
ratification, the goal and preparation identities, and this effect class's settlement
premises (declared for the upstream office's information — they remain Docket's).
Human and JSON renderings derive from one canonical value; an upstream office consumes
only the JSON. **Emitting a request mints nothing and grants nothing.**

**`ag.docket-issuance:v1`** — the issuance record. The exact signed body travels
base64url-encoded inside the envelope, so verification never depends on two
canonicalizers agreeing. The body binds the issuance and decision identities, issuer
principal and key, decision context, principal chain, catalog target, the request's
identity in *both* canonical digest domains, Docket's own binding fields, issue and
expiry times, the upstream office's authorization premises, its residual-obligation
status and items, its own authority-consumption record, and `decision: "admitted"`.

## What Docket verifies — and does not re-evaluate

`docket authz accept --attempt <id> --issuance <file> [--request <file>] [--trust <file>]`
checks, in order: supported schema; a **trusted issuer** from the configured trust file
(`<state>/authz-issuers.json` by default: issuer principal, key id, canonical
base64url Ed25519 public key); the Ed25519 signature over the exact body bytes **under
the trusted key** — a record cannot nominate its own verifier; `decision = admitted`;
freshness against the runtime clock; the supported request schema; and then every
Docket-owned field against **Docket's own stored attempt** — attempt id, prepared
digest, effect class, repository, target ref, basis, admitted paths. The issuance is
never its own yardstick. With `--request`, Docket additionally confirms the issuance
names exactly the request bytes it exported.

Docket does **not** re-run the upstream policy question. It evaluates no catalog, no
principal-chain authority, and no judgement about whether the decision was wise. Those
are the upstream office's; Docket checks authenticity, freshness, and exact binding.

Refusals are typed and mint nothing: unsupported schema, malformed record, untrusted
issuer, failed authentication, not-admitted decision, expiry, binding mismatch (naming
the field, what Docket holds, and what the record named), unsupported request schema,
inconsistent residual set, issuance substitution, already-minted.

## Standing, replay, and consumption

On success Docket mints **its own** grant — local, bound to the exact attempt and
prepared digest, single-use, expiring no later than the issuance. The issuance is a
recorded *basis*; it is never presented to the broker and never becomes a token.

- One issuance justifies at most one grant, for one attempt (enforced by a unique
  index). A second attempt cannot reuse it.
- Re-presenting the same issuance is idempotent; presenting a **different signed body**
  under an accepted issuance identity is a substitution refusal.
- The upstream office's authority consumption is its own fact, carried as a record.
  Docket never consumes or re-animates upstream authority.
- The minted grant is thereafter an ordinary Docket grant: consumed exactly once by
  ratification, refusing on replay like any other.

The governed-loop issuance (`ag.governed-loop.issuance/v2`, accepted by
`docket governed-loop accept`) is a different record with the same rule: it carries a
signed `not_after_unix_ms`, and Docket refuses to begin the effect at or after it,
checking immediately before custody and again immediately before `execute`. See
[local execution standing](local-execution-standing.md#ag-issuance-not-after).

## Premises and residual obligations

Upstream **authorization** premises and this effect class's **settlement** premises are
different kinds of thing and stay separate everywhere: stored separately, rendered
separately, and translated separately by downstream consumers. Docket carries upstream
premises verbatim and **never claims to have verified them**.

Upstream **residual obligations** are carried in the upstream office's own vocabulary,
never coerced into Docket's `ObligationKind`, and never discharged by execution or
import. The status distinguishes *none recorded* from *unrepresented* — an office that
cannot express residuals is recorded as such, so absence is never mistaken for a
finding.

## Dual digests

The request's identity travels in two canonical domains: Docket's plain byte digest and
the upstream office's own canonical digest. Both are stored and rendered; neither is
recomputed from the other, and neither is interchangeable with Docket's prepared-attempt
transcript digest. Docket compares only digests it computes itself.

## Dossier

The `authorization` block was added in **`gwr:attempt-dossier:v2`**. v1 is a closed
schema whose consumers refuse unknown fields, so carrying these facts honestly required
a version, not an extension; historical v1 dossiers remain readable by their consumers
unchanged. The block states the authorization source and, for an upstream issuance, its
identities, issuer, both digests, times, premises, residual status and items, the
upstream consumption record, and explicitly what the authorization establishes and what
it does not.
