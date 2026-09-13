# Local execution standing for governed-loop custody

This deployment profile is Docket-local. It does not generalize Constellation
Standing, replace AG authorization or review, or grant executor success.

An operator prospectively grants one permission for an exact campaign,
occurrence, program, work schema, work, subject and scope. The grant must expire
within 300 seconds and cannot be retimed. Revocation and supersession append
immutable revisions. The resolver reads the selected revision and returns the
existing V1 standing response; it never grants on request.

Use `docket governed-loop standing-grant` before the AG spend, supplying every
exact tuple field plus `--operator`, `--issued-at-unix-ms`, and
`--expires-at-unix-ms`. Use `standing-revoke` or `standing-supersede` with the
grant identity and a monotonic `--at-unix-ms`. Deployment tooling generates a
measured zero-argument launcher with `standing-write-launcher`; it captures the
resolver and closed static config from nonsymlink regular files, checks their
enrolled hashes, seals both memfds against content and size changes, and then
executes and reads only those sealed captures.
The selected Python interpreter and its standard library remain trusted
deployment inputs. The launcher generator observes the interpreter hash while
enrolling, but the generated script's shebang does not reverify the already
executing interpreter at runtime; deployment enrollment must pin it separately.

The first prospective grant irreversibly enrolls that Docket state database in
local snapshot-currentness mode and fixes its operator identity and 300-second
maximum. Every later accept against that state requires local backing even when
the caller omits `--require-local-standing-snapshot`; the flag only asserts the
expected mode on a not-yet-enrolled database and cannot select weaker behavior.
Docket requires the exact immutable revision named by the resolver's hashes and
stores its permission identity, revision,
resolution time, expiry, currentness and resolution atomically with custody.
The currentness digest commits the permission identity, immutable revision
identity, status, resolution time and expiry; the resolution digest additionally
commits the subsequently authenticated AG issuance.
`governed-loop standing-snapshot --issuance DIGEST` reads that explicit backing
receipt. Older external-resolver V1 custody remains readable and has no invented
local snapshot.

Snapshot-currentness is the approved rule. Revocation committed after a
successful resolution is non-retroactive for that custody attempt. A concurrent
revocation appends a new revision; it does not mutate the exact revision already
observed and retained with custody. Before resolution, absent, revoked,
superseded, expired, future-dated, ambiguous, or mismatched permission state
fails closed. After custody, executor uncertainty uses the retained same-attempt
reconciliation path and never re-resolves standing or redispatches mechanics.
