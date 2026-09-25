#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble the Docket release tarball deterministically.

Runs inside the pinned builder image with its /usr/bin/python3 (standard
library only). Inputs are the release binaries, the source tree, the vendored
crate sources and the `cargo metadata` document written by the build step.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import tarfile

COMPONENT = "docket"
BINARIES = ("docket", "docket-local-standing-resolver")
DOCS = (
    "docs/governed-runtime/local-execution-standing.md",
    "docs/governed-runtime/operator-runbook.md",
    "docs/governed-runtime/upstream-authorization.md",
    "docs/governed-runtime/executor-transport-v1.md",
    "docs/governed-runtime/trust-model.md",
)
LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "COPYRIGHT")
LIMITATIONS = [
    "governed-loop surface only: gwr-git-broker is not shipped, so the git broker workflow "
    "(dispatch/observe/recover of git ref effects) is not supported from this artifact",
    "no service unit: docket runs as a subprocess of AG under the cohort account",
    "the snapshot bound (30 000 ms) and grant lifetime cap (300 000 ms) are compiled constants",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dependency_closure(metadata: dict, root_name: str) -> list[dict]:
    """Normal and build dependencies of the shipped package, never dev-only."""
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root = next(pid for pid, package in packages.items() if package["name"] == root_name)
    seen: set[str] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            kinds = {kind["kind"] for kind in dep["dep_kinds"]}
            if kinds - {"dev"}:
                stack.append(dep["pkg"])
    return sorted((packages[pid] for pid in seen if packages[pid]["source"]),
                  key=lambda package: (package["name"], package["version"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--binaries", type=pathlib.Path, required=True)
    parser.add_argument("--vendor", type=pathlib.Path, required=True)
    parser.add_argument("--metadata", type=pathlib.Path, required=True)
    parser.add_argument("--build-identity", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    top = f"{COMPONENT}-{args.version}"
    files: dict[str, tuple[bytes, int]] = {}
    for name in BINARIES:
        files[f"bin/{name}"] = ((args.binaries / name).read_bytes(), 0o755)
    for name in ("LICENSE", "NOTICE"):
        files[name] = ((args.source / name).read_bytes(), 0o644)
    for relative in DOCS:
        files[f"share/doc/{pathlib.PurePath(relative).name}"] = ((args.source / relative).read_bytes(), 0o644)
    files["README.md"] = ((args.source / "packaging/release/PACKAGE-README.md").read_bytes(), 0o644)
    metadata = json.loads(args.metadata.read_text())
    third_party = []
    for package in dependency_closure(metadata, "gwr-local"):
        crate = f"{package['name']}-{package['version']}"
        directory = args.vendor / crate
        notices = sorted(entry.name for entry in directory.iterdir()
                         if entry.is_file() and entry.name.upper().startswith(LICENSE_PREFIXES))
        for notice in notices:
            files[f"THIRD_PARTY_NOTICES/{crate}/{notice}"] = ((directory / notice).read_bytes(), 0o644)
        third_party.append({"crate": package["name"], "version": package["version"],
                            "license": package.get("license"), "notice_files": notices})
    identity = json.loads(args.build_identity.read_text())
    build_info = {
        "schema": "docket.release-build-info/v1",
        "component": COMPONENT,
        "version": args.version,
        **identity,
        "binaries": {name: {"path": f"bin/{name}", "sha256": sha256(files[f"bin/{name}"][0]),
                            "bytes": len(files[f"bin/{name}"][0])} for name in BINARIES},
        "third_party": third_party,
        "limitations": LIMITATIONS,
    }
    files["BUILD-INFO.json"] = ((json.dumps(build_info, indent=2, sort_keys=True) + "\n").encode(), 0o644)
    sums = "".join(f"{sha256(data)}  {name}\n" for name, (data, _) in sorted(files.items()))
    files["SHA256SUMS"] = (sums.encode(), 0o644)

    directories = {top}
    for name in files:
        parts = pathlib.PurePosixPath(name).parts[:-1]
        for index in range(1, len(parts) + 1):
            directories.add(f"{top}/" + "/".join(parts[:index]))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        entries = [(directory, None, 0o755) for directory in directories]
        entries += [(f"{top}/{name}", data, mode) for name, (data, mode) in files.items()]
        for name, data, mode in sorted(entries, key=lambda entry: entry[0]):
            info = tarfile.TarInfo(name)
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = mode
            if data is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=0) as stream:
        stream.write(raw.getvalue())
    args.out.mkdir(parents=True, exist_ok=True)
    tarball = args.out / f"{top}-linux-amd64.tar.gz"
    tarball.write_bytes(compressed.getvalue())
    (args.out / "BUILD-INFO.json").write_bytes(files["BUILD-INFO.json"][0])
    print(json.dumps({"tarball": tarball.name, "sha256": sha256(compressed.getvalue())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
