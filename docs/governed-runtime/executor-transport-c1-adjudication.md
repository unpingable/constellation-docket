# Executor transport C1 preimplementation adjudication

Status: binding preimplementation amendment for
`docket.governed-executor-transport/v1`.

This amendment resolves the questions found by the C1 archaeology pass. It
does not change AG authorization, Docket attempt custody, executor mechanics,
or any existing wire bytes.

1. Docket owns marker uniqueness at issuance. Cross-attempt marker reuse is
   outside the valid Docket-issued domain. V1 executors must bind an attempt
   exactly to its marker and refuse a same-attempt substitution, but need not
   maintain a store-global marker uniqueness index. An executor may enforce
   that stronger local invariant.
2. Recovery outcomes are evidence-sensitive. `failure` is required when the
   executor's qualified durable evidence proves non-occurrence or a definite
   terminal failure. `success` is required when that evidence proves the exact
   effect occurred. `indeterminate` is required when neither is proved.
3. The existing closed, untagged dispatch and outcome objects are structural
   V1. Their schema identities are external. An in-band schema or version
   member would be a future V2 and is an unknown-field refusal under V1.
4. V1 input is duplicate-free semantic JSON with the exact closed field set,
   types, and digest syntax. Input need not already be JCS. Executors continue
   to emit canonical JCS outcomes, but V1 gives dispatch or outcome bytes no
   retroactive identity.
5. Executor stdout is limited to 1 MiB before JSON parsing. Overflow is a
   transport refusal, never an executor-declared outcome. Docket maps that
   refusal through its existing indeterminate custody behavior.

The canonical specification and corpus implement only these decisions. C2
layering, AG pure-model ownership, VM transport, and shared runtime code remain
out of scope.
