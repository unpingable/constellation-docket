# Execution-standing ownership and enrollment

Owner decision, 2026-10-01, recorded for [Docket #3](https://github.com/unpingable/constellation-docket/issues/3).

Docket does not originate or reinterpret execution authority. The deployment authority owns the execution-standing principal and an enrolled projection. Docket consumes and enforces its exact principal, currentness and revocation result. Docket owns attempt custody, one delivery, settlement and reconciliation. Reconciliation observes an existing attempt without new standing and cannot redispatch.

For the fixed M2 local deployment, the accountable principal is the release operator controlling root-owned enrollment and projection files. No external provider or historical standing-grant API participates. This is an explicit installation trust premise: root can replace enrollment and executable code. Same-root mutation is not constrained by this adapter.

`docket-standing-resolver` takes no arguments and reads `docket-standing-resolver.enrollment.json` beside its installed executable. Enrollment has exactly `schema` (`docket.execution-standing-enrollment/v1`), `principal` (nonempty), and `projection` (absolute path). The projection has exactly `schema` (`docket.owner-execution-standing-projection/v1`), the enrolled `principal`, an owner-assigned `generation`, and `resolution`: the existing complete `docket.governed-loop.execution-standing-resolution/v1` response.

The owner supplies standing identity, currentness identity, resolved/expiry times and status. The adapter rereads the snapshot on each new acceptance, verifies the complete issuance identity and exact campaign/occurrence/subject/scope binding, and refuses noncurrent, revoked, absent, superseded or expired results. There is no grant not enrolled by the owner, wildcard, inferred authority or automatic refresh. The owner replaces the snapshot atomically for changes and revocation; generation labels are evidence, not a monotonicity guarantee. A monotone deployment clock and timely owner publication remain premises. Revocation after custody cannot undo an already delivered effect.

Enrollment/projection must be root-owned regular files without group/other write permission, beneath root-owned directories without group/other write permission; symlinks are refused. Configuration is selected by installation, never work/request/environment fields. The package installs the inert reader only. Without explicit enrollment it refuses.

The ordinary projection implementation retains the exact-binding/currentness/instrument separation from the sealed September projection specimen. No campaign runner, test harness, predecessor implementation or authority API is imported.

## Owner-enrolled bounded grant (DK-02 amendment, 2026-10-03)

Owner decision, 2026-10-03: "You authorize the remediation envelope once; machinery may instantiate individual attempts inside that envelope." The DK-02 sentence above now reads "no grant not enrolled by the owner": the owner may enroll one bounded grant, and Docket derives one standing per presented AG issuance from it. Ownership is unchanged: the owner holds principal, currentness, revocation and the grant's bounds; Docket enforces them and never originates or enlarges authority. `validate_standing`, `make_custody`, the one-standing/one-issuance custody table and settlement are unchanged and apply to every derived answer exactly as to a per-issuance projection.

`docket-standing-grant-resolver` is a sibling of `docket-standing-resolver`. It takes no arguments, reads the request on stdin, and reads `docket-standing-grant-resolver.enrollment.json` beside its installed executable. Selecting it is a root reseal of the AG runtime profile (its path and bytes are pinned there like any standing resolver). The per-issuance projection reader is unchanged and remains available.

Enrollment has exactly `schema` (`docket.execution-standing-grant-enrollment/v1`), `principal` (nonempty), `grant` (absolute path) and `grant_sha256` (`sha256:` followed by the lowercase hex SHA-256 of the exact grant file bytes, as printed by `sha256sum`). The grant has exactly:

| Field | Meaning |
|---|---|
| `schema` | `docket.owner-execution-standing-grant/v1` |
| `grant_id` | owner label, 1-128 of `[A-Za-z0-9._/:-]` |
| `principal` | must equal the enrollment principal |
| `subject`, `scope` | exact AG subject and scope digests |
| `work_schema` | exact AG work schema |
| `not_before_unix_ms`, `expires_at_unix_ms` | validity window, `not_before <= now < expires_at` |
| `max_uses` | 1-10000 distinct issuances over the grant's life |
| `standing_ttl_ms` | 1-600000; lifetime of one derived answer, never beyond `expires_at` |
| `revocation_marker` | absolute path; the grant is revoked while anything exists there |
| `use_journal` | absolute path of a directory dedicated to this grant's uses |

For each request the resolver rereads the enrollment and grant, refuses unless the grant bytes match the pin, then checks: request schema and complete issuance identity; revocation marker absent (its directory must be owner-trusted); `not_before <= now < expires_at`; issuance `subject`, `scope` and `work_schema` equal the grant. It then takes an exclusive lock on the journal directory and verifies the whole journal. If the issuance is already journaled it returns the same answer again and consumes nothing. Otherwise, if fewer than `max_uses` entries exist, it creates the next entry `use-NNNNNN.json` with `O_EXCL`, mode 0444, fsyncs it and the directory, and only then answers. Refusals print `execution-standing refused: <reason>` on stderr, exit 2 and print no standing: `execution-standing-grant-digest-mismatch`, `-document`, `-enrollment`, `-revoked`, `-revocation-reference`, `-not-yet-valid`, `-expired`, `-subject-mismatch`, `-scope-mismatch`, `-work-schema-mismatch`, `-exhausted`, `-clock-regression`, `-journal-*`, and the shared owner-file reasons.

A journal entry (`docket.execution-standing-grant-use/v1`) records the grant digest and id, `use_index`, `previous` (SHA-256 of the previous entry's bytes), the issuance, campaign, occurrence, subject, scope, work schema and `derived_at_unix_ms`. The journal is accepted only as contiguous, owner-owned, non-group/other-writable, non-symlink, canonical, hash-chained entries of this exact grant with distinct issuances and nondecreasing times inside the window; anything else (edited, reordered or deleted earlier entries, foreign-grant entries, extra files, loose permissions, a missing directory) fails closed for every issuance. A use is counted when standing is first derived for an issuance, before Docket commits custody, so the count can only exceed actual custody.

The answer is the existing `docket.governed-loop.execution-standing-resolution/v1` with status `current`: `execution_standing = H("docket.grant-execution-standing/v1", {grant: grant_sha256, issuance})`, `resolved_at` = the journaled derivation time, `expires_at = min(resolved_at + standing_ttl_ms, grant expires_at)`, and `currentness`/`resolution` digests over the grant, use entry and answer. Because the derivation time is journaled, rederiving the same issuance yields byte-identical output while the grant still holds and the answer has not expired. The standing names exactly one issuance, so Docket's binding check refuses it for any other issuance and its custody table refuses a second custody for the same standing.

### Grant enrollment procedure

1. Read the exact subject and scope digests and work schema from the AG exact-work catalog entry the grant serves; AG's catalog separately pins the admissible plan digests (and so the unit).
2. Create a root-owned directory without group/other write for the grant, e.g. `install -d -o root -g root -m 0755 /etc/<deployment>/standing`, and a dedicated empty journal, e.g. `install -d -o root -g root -m 0700 /var/lib/<deployment>/standing-grant-uses`. A new or changed grant gets a new, empty journal; an existing journal of another grant digest refuses.
3. Write the grant JSON as root, mode 0644, with `revocation_marker` naming an absent path in an owner-trusted directory.
4. Pin it: `printf 'sha256:%s\n' "$(sha256sum < grant.json | cut -d' ' -f1)"`, and write `docket-standing-grant-resolver.enrollment.json` beside the installed resolver (root, 0644) with the principal, grant path and pin.
5. Name `docket-standing-grant-resolver` as the Docket standing resolver in the AG runtime-profile enrollment and reseal the profile.
6. Revoke by creating the marker (`touch`), or by removing the enrollment. Replace a grant only by writing a new grant, a new journal and a new pin. Never grant the consumer write access to the grant, its directory, the enrollment or the journal.

Declared limits, as for the projection reader: all-root co-located execution; root can replace enrollment, grant, journal and executable code, and in particular can delete or rewrite the newest journal entry without detection; no OS principal separation between the consumer, the AG issuer key and Docket; a forward-moving clock and timely owner revocation are premises; revocation after custody cannot undo a delivered effect.
