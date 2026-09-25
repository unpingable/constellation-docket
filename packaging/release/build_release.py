#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the Docket release tarball twice, offline, and prove byte equality.

Each build runs in the pinned Debian 12 Rust 1.94.0 image by digest with
`--network none`, from its own clean clone of the named commit, against one
vendored crate snapshot, with path remapping and a fixed SOURCE_DATE_EPOCH.
The tarball is assembled in the same image (`assemble.py`). Outputs:
the tarball, SHA256SUMS, `build-receipt.v1.json` and the build logs.

    python3 packaging/release/build_release.py \
        --source-a CLONE_A --source-b CLONE_B --commit FULL_SHA \
        --vendor VENDOR_DIR --scratch ROOT_FS_DIR --output NEW_DIR
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

SCHEMA = "constellation.docket.release-build/v1"
COMPONENT = "docket"
VERSION = "0.1.0"
IMAGE_ID = "sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379"
IMAGE_REPO_DIGEST = "rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f"
TOOLCHAIN = "1.94.0"
SOURCE_DATE_EPOCH = "1700000000"
BINARIES = ("docket", "docket-local-standing-resolver")
TARBALL = f"{COMPONENT}-{VERSION}-linux-amd64.tar.gz"
CARGO_ARGUMENTS = ["build", "--release", "--locked", "--offline", "--jobs", "4", "-p", "gwr-local",
                   "--bin", "docket", "--bin", "docket-local-standing-resolver"]
METADATA_ARGUMENTS = ["metadata", "--locked", "--offline", "--format-version", "1",
                      "--filter-platform", "x86_64-unknown-linux-gnu"]
TRACKED = ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "crates/gwr-local/build.rs",
           "packaging/release/assemble.py", "packaging/release/build_release.py")


class Refusal(RuntimeError):
    pass


def run(command: list[str], *, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, check=False)
    if result.returncode != 0:
        raise Refusal(f"command refused ({result.returncode}): {command!r}\n"
                      + result.stderr.decode(errors="replace")[-4000:])
    return result


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_env(commit: str) -> dict[str, str]:
    return {
        "CARGO_HOME": "/cargo-home",
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
        "CARGO_TARGET_DIR": "/build",
        "CFLAGS": "-ffile-prefix-map=/vendor=/cargo-vendor -ffile-prefix-map=/build=/cargo-build",
        "DOCKET_SOURCE_COMMIT": commit,
        "HOME": "/tmp/docket-builder-home",
        "LC_ALL": "C.UTF-8",
        "RUSTFLAGS": "--remap-path-prefix=/src=. --remap-path-prefix=/vendor=/cargo-vendor "
                     "--remap-path-prefix=/cargo-home=/cargo-home",
        "RUSTUP_TOOLCHAIN": TOOLCHAIN,
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        "TZ": "UTC",
    }


def cargo_config() -> str:
    return ('[net]\noffline = true\n\n[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
            '[source.vendored-sources]\ndirectory = "/vendor"\n')


def tree_digest(root: pathlib.Path) -> tuple[str, int]:
    if not root.is_dir() or root.is_symlink():
        raise Refusal("vendor input is not one physical directory")
    digest = hashlib.sha256(b"docket-vendor-tree-v1\0")
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise Refusal(f"vendor input contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        for part in (relative, (metadata.st_mode & 0o777).to_bytes(4, "big"), data):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
        count += 1
    if count == 0:
        raise Refusal("vendor input is empty")
    return digest.hexdigest(), count


def source_facts(source: pathlib.Path, commit: str) -> dict[str, Any]:
    head = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.decode().strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=source).stdout.decode().strip()
    if head != commit:
        raise Refusal(f"{source}: HEAD {head} is not the named commit {commit}")
    if run(["git", "status", "--porcelain", "--ignored"], cwd=source).stdout:
        raise Refusal(f"{source}: clone is not clean")
    return {"commit": head, "tree": tree, "clean": True,
            "tracked_inputs_sha256": {name: sha256_file(source / name) for name in TRACKED}}


def image_facts() -> dict[str, Any]:
    records = json.loads(run(["docker", "image", "inspect", IMAGE_ID]).stdout)
    if len(records) != 1 or records[0].get("Id") != IMAGE_ID:
        raise Refusal("builder image identity differs")
    if IMAGE_REPO_DIGEST not in records[0].get("RepoDigests", []):
        raise Refusal("builder image repository digest is absent")
    return {"image_id": IMAGE_ID, "repository_digest": IMAGE_REPO_DIGEST, "toolchain": TOOLCHAIN,
            "network": "none", "pull": "never", "read_only_root": True}


def docker_argv(env: dict[str, str], mounts: list[tuple[str, str, str]], command: list[str]) -> list[str]:
    argv = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,exec", "--hostname", "docket-builder",
            "--user", f"{os.getuid()}:{os.getgid()}"]
    for key, value in sorted(env.items()):
        argv += ["-e", f"{key}={value}"]
    for host, container, mode in mounts:
        argv += ["-v", f"{host}:{container}:{mode}"]
    return argv + ["-w", "/src", IMAGE_ID] + command


def build_once(label: str, source: pathlib.Path, vendor: pathlib.Path, scratch: pathlib.Path,
               commit: str) -> dict[str, Any]:
    case = scratch / label
    for sub in ("cargo-home", "build", "out"):
        (case / sub).mkdir(parents=True)
    (case / "cargo-home" / "config.toml").write_text(cargo_config())
    mounts = [(str(source), "/src", "ro"), (str(vendor), "/vendor", "ro"),
              (str(case / "cargo-home"), "/cargo-home", "rw"), (str(case / "build"), "/build", "rw"),
              (str(case / "out"), "/out", "rw")]
    env = build_env(commit)
    script = (
        "set -eu; cargo " + " ".join(CARGO_ARGUMENTS)
        + "; cargo " + " ".join(METADATA_ARGUMENTS) + " > /build/metadata.json"
        + "; rustc --version > /build/rustc-version.txt"
    )
    built = run(docker_argv(env, mounts, ["sh", "-c", script]))
    identity = {
        "source_commit": commit,
        "source_tree": run(["git", "rev-parse", "HEAD^{tree}"], cwd=source).stdout.decode().strip(),
        "rustc": (case / "build" / "rustc-version.txt").read_text().strip(),
        "builder_image": IMAGE_REPO_DIGEST,
        "source_date_epoch": int(SOURCE_DATE_EPOCH),
        "cargo_profile": "release",
    }
    (case / "build" / "build-identity.json").write_text(json.dumps(identity, sort_keys=True))
    assembled = run(docker_argv(env, mounts, [
        "python3", "/src/packaging/release/assemble.py", "--version", VERSION, "--source", "/src",
        "--binaries", "/build/release", "--vendor", "/vendor", "--metadata", "/build/metadata.json",
        "--build-identity", "/build/build-identity.json", "--out", "/out"]))
    (case / "build.log").write_bytes(built.stdout + built.stderr + assembled.stdout + assembled.stderr)
    binaries = {}
    for name in BINARIES:
        path = case / "build" / "release" / name
        versions = run(["readelf", "--version-info", str(path)]).stdout.decode()
        glibc = [(int(a), int(b)) for a, b in re.findall(r"Name: GLIBC_(\d+)\.(\d+)", versions)]
        newest = max(glibc) if glibc else None
        if newest is not None and newest > (2, 36):
            raise Refusal(f"{name} requires glibc {newest}, beyond Debian 12")
        info = json.loads(run([str(path), "--build-info"]).stdout)
        version_line = run([str(path), "--version"]).stdout.decode().strip()
        if info.get("source_commit") != commit or info.get("cargo_profile") != "release" \
                or info.get("debug_assertions") is not False or info.get("component") != name:
            raise Refusal(f"{name} build-info does not name the release build of {commit}")
        if version_line != f"{name} {VERSION} {commit}":
            raise Refusal(f"{name} --version is {version_line!r}")
        binaries[name] = {"sha256": sha256_file(path), "bytes": path.stat().st_size,
                          "maximum_glibc": None if newest is None else f"GLIBC_{newest[0]}.{newest[1]}",
                          "build_info": info, "version": version_line}
    artifacts = {name: {"sha256": sha256_file(case / "out" / name), "bytes": (case / "out" / name).stat().st_size}
                 for name in (TARBALL, "BUILD-INFO.json")}
    return {"binaries": binaries, "artifacts": artifacts, "env": env,
            "argv": docker_argv(env, [("<SOURCE>", "/src", "ro"), ("<VENDOR>", "/vendor", "ro"),
                                      ("<CARGO_HOME>", "/cargo-home", "rw"), ("<BUILD>", "/build", "rw"),
                                      ("<OUT>", "/out", "rw")], ["sh", "-c", script])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-a", type=pathlib.Path, required=True)
    parser.add_argument("--source-b", type=pathlib.Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--vendor", type=pathlib.Path, required=True)
    parser.add_argument("--scratch", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
            raise Refusal("--commit must be a full 40-hex commit id")
        if args.output.exists():
            raise Refusal("output already exists")
        sources = [args.source_a.resolve(strict=True), args.source_b.resolve(strict=True)]
        if sources[0] == sources[1]:
            raise Refusal("the two builds need two independent clones")
        facts = [source_facts(source, args.commit) for source in sources]
        if facts[0] != facts[1]:
            raise Refusal("the two clones differ")
        vendor = args.vendor.resolve(strict=True)
        vendor_sha, vendor_files = tree_digest(vendor)
        builder = image_facts()
        args.scratch.mkdir(parents=True, exist_ok=True)
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="docket-release.", dir=args.scratch))
        builds = [build_once(label, source, vendor, scratch, args.commit)
                  for label, source in zip(("a", "b"), sources)]
        comparable = [{"binaries": b["binaries"], "artifacts": b["artifacts"]} for b in builds]
        byte_equal = comparable[0] == comparable[1] and \
            (scratch / "a/out" / TARBALL).read_bytes() == (scratch / "b/out" / TARBALL).read_bytes()
        if not byte_equal:
            raise Refusal(f"independent builds differ; scratch kept at {scratch}")
        args.output.mkdir(parents=True)
        shutil.copyfile(scratch / "a/out" / TARBALL, args.output / TARBALL)
        for label in ("a", "b"):
            shutil.copyfile(scratch / label / "build.log", args.output / f"build-{label}.log")
        receipt = {
            "schema": SCHEMA,
            "component": COMPONENT,
            "version": VERSION,
            "source": {**facts[0], "remote": "git@github-unpingable:unpingable/constellation-docket.git"},
            "vendor": {"tree_sha256": vendor_sha, "regular_files": vendor_files, "container_path": "/vendor",
                       "produced_by": "cargo vendor --locked --versioned-dirs (host, before the offline builds)"},
            "builder": {**builder, "host_uid_gid": f"{os.getuid()}:{os.getgid()}",
                        "builder_script_sha256": sha256_file(pathlib.Path(__file__).resolve())},
            "build": {"environment": builds[0]["env"], "cargo_arguments": CARGO_ARGUMENTS,
                      "metadata_arguments": METADATA_ARGUMENTS,
                      "cargo_config_sha256": hashlib.sha256(cargo_config().encode()).hexdigest(),
                      "normalized_docker_argv": builds[0]["argv"]},
            "binaries": builds[0]["binaries"],
            "artifacts": {TARBALL: builds[0]["artifacts"][TARBALL],
                          "BUILD-INFO.json (inside the tarball)": builds[0]["artifacts"]["BUILD-INFO.json"]},
            "reproduction": {"clean_builds": 2, "independent_clones": True, "byte_equal": True,
                             "build_a": comparable[0]["artifacts"], "build_b": comparable[1]["artifacts"]},
            "logs": {f"build-{label}.log": sha256_file(args.output / f"build-{label}.log") for label in ("a", "b")},
        }
        (args.output / "build-receipt.v1.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        sums = "".join(f"{sha256_file(args.output / name)}  {name}\n"
                       for name in (TARBALL, "build-receipt.v1.json"))
        (args.output / "SHA256SUMS").write_text(sums)
        shutil.rmtree(scratch)
        print(json.dumps({"result": "REPRODUCIBLE_RELEASE", "tarball": TARBALL,
                          "sha256": builds[0]["artifacts"][TARBALL]["sha256"]}))
        return 0
    except (OSError, ValueError, Refusal) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
