# Governed-loop CLI package

Build `docket` from one exact locked source export on Ubuntu 22.04, then run
`packaging/build-deb.sh VERSION amd64 BIN_DIR OUT_DIR`. Record the source SHA,
lockfile hash, builder image/toolchain, executable hash and resulting package
hash. Set `SOURCE_DATE_EPOCH` to the source commit timestamp. Inspect ELF
interpreter and library/version requirements; a successful package assembly
does not establish a supported composed runtime.

Set `DOCKET_SOURCE_COMMIT` to the full lowercase source commit and
`DOCKET_BUILD_IDENTITY` to the builder's exact build-receipt identity before
both compilation and package assembly. The latter is a nonempty printable
ASCII identifier of at most 256 bytes, without spaces. For example:

```sh
export DOCKET_SOURCE_COMMIT="<full-source-commit>"
export DOCKET_BUILD_IDENTITY="<build-receipt-id>"
cargo build --locked --release -p gwr-local --bins
packaging/build-deb.sh 0.1.0+candidate.1 amd64 target/release out
```

All three packaged tools support `--build-info` and `--version` without
configuration, enrollment, stdin or state access. `--build-info` reports
`docket.build_info.v1`: component, crate version, source commit, build ID,
compiler, target and debug-assertion flag. Omitted development source/build
inputs are JSON `null`; no Git revision is guessed from a possibly modified
checkout. Malformed declared identities fail compilation. Runtime environment
variables cannot override the compiled identity.

The assembler probes the staged executable copies and refuses unknown or
mismatched source/build IDs, component names, versions, target architectures,
compiler identities or build-profile flags. It records each staged executable's
SHA-256 and probe in `build-identity.json` inside the package and an adjacent
`.build-identity.json` receipt. The existing package checksum binds the complete
package bytes. These fields are builder declarations: the isolated builder
still owns source-export, lockfile, toolchain and artifact correspondence;
the probe alone does not establish that the declared source produced the bytes.

Installation is inert. Enrollment remains explicit: issuer trust, Docket state,
standing resolver, executor program and sealed plan. Experimental VM/session
executors, Git broker/provider workflows and their dependencies are excluded.
Do not pass current signed dispatch through a legacy bare-dispatch adapter.

The package also ships the inert `docket-standing-resolver` owner-projection reader. It installs no enrollment or standing snapshot; see `docs/governed-runtime/execution-standing-enrollment.md`.

It also ships the inert `docket-standing-grant-resolver`, which derives one standing per AG issuance from an owner-enrolled bounded grant. It installs no enrollment, grant or use journal; see the same document.
