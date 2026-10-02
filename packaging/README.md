# Governed-loop CLI package

Build `docket` from one exact locked source export on Ubuntu 22.04, then run
`packaging/build-deb.sh VERSION amd64 BIN_DIR OUT_DIR`. Record the source SHA,
lockfile hash, builder image/toolchain, executable hash and resulting package
hash. Set `SOURCE_DATE_EPOCH` to the source commit timestamp. Inspect ELF
interpreter and library/version requirements; a successful package assembly
does not establish a supported composed runtime.

Installation is inert. Enrollment remains explicit: issuer trust, Docket state,
standing resolver, executor program and sealed plan. Experimental VM/session
executors, Git broker/provider workflows and their dependencies are excluded.
Do not pass current signed dispatch through a legacy bare-dispatch adapter.

The package also ships the inert `docket-standing-resolver` owner-projection reader. It installs no enrollment or standing snapshot; see `docs/governed-runtime/execution-standing-enrollment.md`.
