# Retain work prepared in an existing session

`docket prepare import` retains externally prepared candidate bytes and their
submitted origin. It does not invoke Codex, apply a patch, run tests, admit an
attempt, grant standing, ratify, reserve, dispatch, update a Git ref or prove a
successful outcome. An imported candidate can be inspected before the separate
governed workflow is considered.

Start with an explicitly registered repository and its native work request:

```sh
docket repository register --state /absolute/state --repo /absolute/repository
docket request create --state /absolute/state --repository-id repo-REPLACE \
  --repo /absolute/repository --target-ref refs/heads/result --goal 'Describe the work'
```

Use the actual repository ID and work-request ID returned by those commands.
The request does not already bind a basis. The operator selects an exact Git
commit as the expected basis for this **new** preparation. Docket checks that
it exists as a commit in the currently registered request repository. This
lookup clears Git's defined repository-local environment variables; inherited
`GIT_DIR`, common/object-directory or alternate-object selectors cannot substitute
another repository. Normal repository-owned `.git` and linked-worktree discovery
remain in use. It does
not establish that the external worker actually used it.

The versioned manifest below is unverified external testimony. The importer
checks its request and basis against the explicit CLI coordinates, its repository
against the registered request, and its digest/length against the submitted bytes.
Two matching caller statements prove consistency, not independent provenance.
No provider transcript, tool events, tests or outcome are inferred.

```json
{
  "schema": "gwr:external-candidate:v1",
  "submission_id": "my-session-candidate-1",
  "request": "00000000000000000000000000000000",
  "repository_id": "repo-00000000000000000000000000000000",
  "basis": "0000000000000000000000000000000000000000",
  "content_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "content_length": 0,
  "deadline_unix_ms": 0,
  "origin": {"kind": "external-session", "identity": "actual-session-reference", "tool": "codex"}
}
```

Replace the example identities, digest, byte length and deadline with actual
values. Compute SHA-256 and length over the exact candidate file, not a reencoded
patch. Deadline is an absolute Unix time in milliseconds. `origin.kind` admits
`external-session` or `human`; `origin.identity` is a nonempty supplied reference.
`origin.tool` is optional: omit it when unknown. Origin is never authenticated
by this API. Unknown fields and schemas refuse. Preparation does not determine
whether the patch applies, whether tests pass or whether its claimed work is done.

```sh
docket prepare import --state /absolute/state --request REQUEST_HEX \
  --basis EXACT_COMMIT --manifest /absolute/external.json \
  --patch /absolute/candidate.patch --json
docket prepare inspect --state /absolute/state --run PREPARATION_RUN_HEX --json
```

Both commands print a `gwr:external-preparation:v1` JSON view. It includes the
native run/candidate, exact retained binding, repository locator/target ref,
versioned binding digest and `provenance_trust: submitted_testimony`. Inspection
opens the existing store read-only and verifies the actual retained bytes;
missing or corrupt custody refuses. It never creates or migrates a store.
Provider-created preparations have no external binding and refuse this inspector;
their existing `prepare poll` and governed read interfaces remain available.

`submission_id` is scoped to the logical repository ID. An exact committed
repeat returns the original run/candidate after checking retained bytes. It
does not extend the deadline; a repeat after expiry only reads existing custody.
Changed origin, request, basis, bytes or any other bound field under that identity
refuses. A genuinely distinct submission needs a new identity. A new import
whose deadline has passed refuses. Cancellation before submission is simply not
importing it: the importer starts no external worker and claims no cancellation
of an existing session.

Binding, preparation, candidate and end rows commit in one SQLite transaction.
An interrupted or failed transaction cannot leave a partially accepted native
import. Content-addressed bytes may remain without a committed native reference;
an exact retry verifies them before any acceptance. A corrupt preexisting file
refuses, requiring an operator custody decision; do not delete or overwrite
ambiguous evidence to make a retry pass. After a lost response, repeat the same
manifest and candidate to recover committed custody or perform a safe fresh
transaction. A store error remains an error, not a successful preparation.

Bounds are 16 KiB for the manifest, 8 MiB for candidate bytes, 256 UTF-8 bytes for
submission ID/tool and 4096 bytes for origin identity; empty/control-bearing
strings refuse. Native clock values must fit signed 64-bit milliseconds.
The additive `external_preparation` table uses typed scalar columns and
append-only triggers. Legacy preparations acquire no invented origin or basis.
Its digest is the explicit `gwr:external-preparation-binding:v1` transcript,
independent of JSON field order. Shared positive/refusal and digest vectors live
in `conformance/external-candidate-v1/` and are consumed by native tests.

The bounded claim is retained identity/content custody under the existing
same-UID filesystem and SQLite assumptions. Tests/prose suffice for this local
transaction and provenance boundary; it establishes no external-origin
authentication, worker confinement, useful-output verification or effect authority.
