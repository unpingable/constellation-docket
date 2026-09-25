# Docket release artifact

This tarball carries the two Docket executables used by the Constellation
`reviewed-local-copy/v1` governed loop:

- `bin/docket`: governed-loop custody (`governed-loop accept`, `inspect`,
  `standing-snapshot`, `reconcile-issuance`, `reconcile-attempt`) and the local
  execution standing commands (`standing-grant`, `standing-revoke`,
  `standing-supersede`, `standing-write-launcher`).
- `bin/docket-local-standing-resolver`: the resolver behind the measured
  zero-argument launcher that `standing-write-launcher` generates.

Both answer `--version` (component, version, full source commit) and
`--build-info` (JSON). `BUILD-INFO.json` binds the binaries' sha256 to the source
commit, toolchain and builder image; `SHA256SUMS` covers every file here.

Install by extracting to a root-owned prefix, for example
`/opt/constellation/cohorts/<cohort>/docket/`. There is no service unit and no
configuration at install: AG invokes `docket` as a subprocess under the cohort
account. See `share/doc/local-execution-standing.md` for the commands, the
declared 30 s standing-snapshot bound and the AG issuance not-after rule, and
`share/doc/operator-runbook.md` for operations.

Not included: `gwr-git-broker` and the git-ref workflow it serves.
