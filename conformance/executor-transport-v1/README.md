# Governed-executor transport V1 conformance corpus

Canonical owner: Docket.

Contract: `docket.governed-executor-transport/v1`.

`dispatch.schema.json` and `outcome.schema.json` describe the untagged closed
V1 objects. `corpus.json` is the transport-neutral executable fixture index.
Its `decode_cases` carry exact JSON bytes as strings and an exact accept/refuse
expectation. `lifecycle_cases` state the persistent evidence premise, required
result, and whether mechanics may run.

Lifecycle results are intentionally evidence-sensitive. A nominal crash point
does not override an executor's qualified durable evidence. The
`changed-attempt-reused-marker` case is outside valid Docket-issued input and
does not impose a global marker index on executors.

Consumers run this corpus with independent parsers and lifecycle harnesses. No
Docket runtime implementation is shared with them.
