#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build Docket from this checkout, run the indeterminate-effect demo, then check it.
# Needs: cargo (the repository pins Rust 1.94.0), a C compiler, python3 (3.11+), openssl (3.x).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
for tool in cargo cc python3 openssl; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool (see README.md)" >&2; exit 1; }
done

commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)
if [[ -n "$commit" && -z "$(git -C "$repo" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
  export DOCKET_SOURCE_COMMIT="$commit"
fi
echo "Building Docket from source (the first build takes a few minutes)..."
start=$SECONDS
(cd "$repo" && cargo build --release --locked --quiet -p gwr-local --bin docket --bin docket-local-standing-resolver)
echo "Built in $((SECONDS - start))s."
echo

out="$here/out/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
python3 -u "$here/demo.py" --docket-bin "$repo/target/release" --out "$out" | tee "$out/transcript.txt"
echo
echo "Independent check of the retained records:"
python3 -u "$here/check.py" "$out" --docket "$repo/target/release/docket" | tee "$out/check.txt"
