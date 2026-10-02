# Execution-standing ownership and enrollment

Owner decision, 2026-10-01, recorded for [Docket #3](https://github.com/unpingable/constellation-docket/issues/3).

Docket does not originate or reinterpret execution authority. The deployment authority owns the execution-standing principal and an enrolled projection. Docket consumes and enforces its exact principal, currentness and revocation result. Docket owns attempt custody, one delivery, settlement and reconciliation. Reconciliation observes an existing attempt without new standing and cannot redispatch.

For the fixed M2 local deployment, the accountable principal is the release operator controlling root-owned enrollment and projection files. No external provider or historical standing-grant API participates. This is an explicit installation trust premise: root can replace enrollment and executable code. Same-root mutation is not constrained by this adapter.

`docket-standing-resolver` takes no arguments and reads `docket-standing-resolver.enrollment.json` beside its installed executable. Enrollment has exactly `schema` (`docket.execution-standing-enrollment/v1`), `principal` (nonempty), and `projection` (absolute path). The projection has exactly `schema` (`docket.owner-execution-standing-projection/v1`), the enrolled `principal`, an owner-assigned `generation`, and `resolution`: the existing complete `docket.governed-loop.execution-standing-resolution/v1` response.

The owner supplies standing identity, currentness identity, resolved/expiry times and status. The adapter rereads the snapshot on each new acceptance, verifies the complete issuance identity and exact campaign/occurrence/subject/scope binding, and refuses noncurrent, revoked, absent, superseded or expired results. There is no cached grant, wildcard, inferred authority or automatic refresh. The owner replaces the snapshot atomically for changes and revocation; generation labels are evidence, not a monotonicity guarantee. A monotone deployment clock and timely owner publication remain premises. Revocation after custody cannot undo an already delivered effect.

Enrollment/projection must be root-owned regular files without group/other write permission, beneath root-owned directories without group/other write permission; symlinks are refused. Configuration is selected by installation, never work/request/environment fields. The package installs the inert reader only. Without explicit enrollment it refuses.

The ordinary projection implementation retains the exact-binding/currentness/instrument separation from the sealed September projection specimen. No campaign runner, test harness, predecessor implementation or authority API is imported.
