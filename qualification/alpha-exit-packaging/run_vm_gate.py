#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Clean Debian 12 VM gate for the Docket release artifact.

Follows the style of NQ's release-closure harness: one disposable guest from
the verified read-only base image (qcow2 overlay, cloud-init seed, KVM, user
networking with restrict=on and one SSH hostfwd on 127.0.0.1, qemu -sandbox
on). The guest receives only the release artifacts, the build receipt, the
AG-owned shared issuance vectors and `guest_gate.py`; no source tree, share or
host PATH. Every key and identity is synthetic and generated in the guest.

    python3 qualification/alpha-exit-packaging/run_vm_gate.py \
        --candidate-dir ARTIFACTS --vectors conformance/ag-governed-loop-issuance/v2-vectors.json \
        --ssh-port 23441 --state-dir ROOT_FS_DIR --output NEW_DIR
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
IMAGE = pathlib.Path(
    "/data/git/.campaign-artifacts/constellation-operator-beta-composed-m2-run-002/input/"
    "debian-12-genericcloud-amd64-20260903-2590.qcow2"
)
USER = "docketacceptor"
HOME = f"/home/{USER}"
ARTIFACTS = ("docket-0.1.0-linux-amd64.tar.gz", "SHA256SUMS", "build-receipt.v1.json")
VECTORS_SHA256 = "b715ddcf1d04ca751d8bfb9d81dee1a4dc68db131a7d3c05df3f7f6133eaf513"
PORTS = range(23441, 23450)


class Refusal(Exception):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha(path: pathlib.Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], *, check: bool = True, timeout: float = 600) -> subprocess.CompletedProcess[bytes]:
    done = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    if check and done.returncode != 0:
        raise Refusal(f"command failed ({done.returncode}): {shlex.join(command)}\n"
                      f"{done.stderr.decode(errors='replace')[-2000:]}")
    return done


class Gate:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.out: pathlib.Path = args.output
        self.state: pathlib.Path = args.state_dir
        self.key = self.state / "id_ed25519"
        self.process: subprocess.Popen[bytes] | None = None
        self.command: list[str] = []
        self.facts: dict = {}

    def log(self, message: str) -> None:
        line = f"[{utc_now()}] {message}"
        print(line, flush=True)
        with (self.out / "host.log").open("a") as handle:
            handle.write(line + "\n")

    def ssh_options(self) -> list[str]:
        return ["-i", str(self.key), "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={self.state / 'known_hosts'}", "-o", "LogLevel=ERROR"]

    def ssh(self, command: str, *, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return run(["ssh", *self.ssh_options(), "-o", "ConnectTimeout=5", "-p", str(self.args.ssh_port),
                    f"{USER}@127.0.0.1", command], timeout=timeout, check=check)

    def scp(self, sources: list[pathlib.Path], destination: str) -> None:
        run(["scp", "-q", *self.ssh_options(), "-P", str(self.args.ssh_port), *map(str, sources),
             f"{USER}@127.0.0.1:{destination}"])

    def harness_identity(self) -> dict:
        def git(*arguments: str) -> str | None:
            done = subprocess.run(["git", "-C", str(HERE), *arguments], capture_output=True, text=True)
            return done.stdout.strip() if done.returncode == 0 else None
        return {"commit": git("rev-parse", "HEAD"),
                "dirty_paths": (git("status", "--porcelain", "--", ".") or "").splitlines(),
                "files": {name: sha(HERE / name) for name in ("run_vm_gate.py", "guest_gate.py")}}

    def preflight(self) -> None:
        if self.args.ssh_port not in PORTS:
            raise Refusal("Docket lane SSH ports are 23441-23449")
        for tool in ("qemu-img", "qemu-system-x86_64", "xorriso", "ssh", "scp", "ssh-keygen"):
            if shutil.which(tool) is None:
                raise Refusal(f"required tool absent: {tool}")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise Refusal("/dev/kvm is not accessible")
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", self.args.ssh_port))
            except OSError as error:
                raise Refusal(f"port {self.args.ssh_port} is busy") from error
        if self.out.exists() or self.state.exists():
            raise Refusal("output or state directory exists")
        self.out.mkdir(parents=True)
        self.state.mkdir(parents=True, mode=0o700)
        candidate: pathlib.Path = self.args.candidate_dir
        checked = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=candidate,
                                 capture_output=True)
        if checked.returncode != 0:
            raise Refusal("candidate SHA256SUMS does not verify on the host")
        receipt = json.loads((candidate / "build-receipt.v1.json").read_text())
        if receipt["reproduction"]["byte_equal"] is not True:
            raise Refusal("receipt does not record a byte-equal reproduction")
        if sha(self.args.vectors) != VECTORS_SHA256:
            raise Refusal("shared issuance vectors differ from the pinned corpus")
        expected = None
        for line in (IMAGE.parent / "SHA512SUMS").read_text().splitlines():
            digest, _, name = line.strip().partition("  ")
            if name == IMAGE.name:
                expected = digest
        actual = sha(IMAGE, "sha512")
        if expected != actual:
            raise Refusal("base image SHA-512 differs from SHA512SUMS")
        if os.access(IMAGE, os.W_OK):
            raise Refusal("base image must not be writable")
        self.facts = {"started": utc_now(), "harness": self.harness_identity(),
                      "candidate": {"directory": str(candidate),
                                    "receipt_sha256": sha(candidate / "build-receipt.v1.json"),
                                    "tarball_sha256": sha(candidate / ARTIFACTS[0]),
                                    "source_commit": receipt["source"]["commit"]},
                      "vectors": {"path": str(self.args.vectors), "sha256": VECTORS_SHA256},
                      "image": {"path": str(IMAGE), "sha512": actual}, "ssh_port": self.args.ssh_port}

    def boot(self) -> None:
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "docket-vm-gate", "-f", str(self.key)])
        public = self.key.with_suffix(".pub").read_text().strip()
        (self.state / "meta-data").write_text("instance-id: docket-vm-gate\nlocal-hostname: docket-gate\n")
        (self.state / "user-data").write_text(f"""#cloud-config
disable_root: true
hostname: docket-gate
package_update: false
package_upgrade: false
ssh_pwauth: false
users:
  - name: {USER}
    groups: [sudo]
    lock_passwd: true
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - "{public}"
""")
        run(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(self.state / "seed.iso"), "-volid", "cidata",
             "-joliet", "-rock", str(self.state / "user-data"), str(self.state / "meta-data")])
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(IMAGE), "-F", "qcow2",
             str(self.state / "overlay.qcow2")])
        self.command = [
            "qemu-system-x86_64", "-name", "docket-vm-gate,process=docket-vm-gate", "-no-user-config",
            "-nodefaults", "-accel", "kvm", "-machine", "q35", "-cpu", "host", "-smp", "2", "-m", "2048",
            "-display", "none", "-monitor", "none", "-serial", f"file:{self.state / 'serial.log'}",
            "-drive", f"if=virtio,file={self.state / 'overlay.qcow2'},format=qcow2,cache=none,aio=threads",
            "-drive", f"if=virtio,file={self.state / 'seed.iso'},format=raw,readonly=on",
            "-netdev", f"user,id=mgmt,restrict=on,hostfwd=tcp:127.0.0.1:{self.args.ssh_port}-:22",
            "-device", "virtio-net-pci,netdev=mgmt,mac=52:54:00:9c:04:41",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ]
        (self.out / "qemu-command.txt").write_text(shlex.join(self.command) + "\n")
        self.process = subprocess.Popen(self.command, stdout=(self.state / "qemu.stdout.log").open("wb"),
                                        stderr=(self.state / "qemu.stderr.log").open("wb"), start_new_session=True)
        self.log(f"started guest pid {self.process.pid} on 127.0.0.1:{self.args.ssh_port}")
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise Refusal("guest exited: " + (self.state / "qemu.stderr.log").read_text()[-800:])
            try:
                if self.ssh("true", timeout=30, check=False).returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(3)
        else:
            raise Refusal("guest SSH not reachable")
        self.ssh("cloud-init status --wait >/dev/null; cloud-init status", timeout=900, check=False)
        self.ssh(f"mkdir -p {HOME}/candidate {HOME}/inputs {HOME}/bin")
        self.scp([self.args.candidate_dir / name for name in ARTIFACTS], f"{HOME}/candidate/")
        self.scp([self.args.vectors], f"{HOME}/inputs/v2-vectors.json")
        self.scp([HERE / "guest_gate.py"], f"{HOME}/bin/")
        self.log("guest ready; inputs copied")

    def gate(self) -> int:
        done = self.ssh(f"sudo /usr/bin/python3.11 -I {HOME}/bin/guest_gate.py {HOME}", timeout=3600, check=False)
        (self.out / "guest-stdout.log").write_bytes(done.stdout)
        (self.out / "guest-stderr.log").write_bytes(done.stderr)
        self.ssh(f"sudo tar -C {HOME} -czf /tmp/gate.tgz gate && sudo chmod 644 /tmp/gate.tgz")
        run(["scp", "-q", *self.ssh_options(), "-P", str(self.args.ssh_port), f"{USER}@127.0.0.1:/tmp/gate.tgz",
             str(self.state / "gate.tgz")])
        run(["tar", "-C", str(self.out), "-xzf", str(self.state / "gate.tgz"), "--exclude=gate/sign-tmp",
             "--exclude=gate/*.der", "--exclude=gate/p01"])
        guest = json.loads((self.out / "gate" / "result.json").read_text())
        summary = {o: sum(1 for c in guest["cases"] if c["outcome"] == o) for o in ("PASS", "FAIL")}
        self.facts["finished"] = utc_now()
        (self.out / "GATE-RESULT.json").write_text(json.dumps(
            {"schema": "docket.release-vm-gate/v1", "facts": self.facts, "guest_facts": guest["facts"],
             "summary": summary, "qemu_command": self.command, "cases": guest["cases"]},
            indent=2, sort_keys=True) + "\n")
        self.log(f"summary {summary}")
        return 0 if summary["FAIL"] == 0 and summary["PASS"] == len(guest["cases"]) else 1

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            try:
                self.ssh("sudo systemctl poweroff", timeout=20, check=False)
                self.process.wait(timeout=60)
            except Exception:  # noqa: BLE001
                self.process.kill()
                self.process.wait(timeout=30)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--candidate-dir", type=pathlib.Path, required=True)
    parser.add_argument("--vectors", type=pathlib.Path, required=True)
    parser.add_argument("--ssh-port", type=int, default=23441)
    parser.add_argument("--state-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    gate = Gate(parser.parse_args())
    try:
        gate.preflight()
        gate.boot()
        return gate.gate()
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2
    finally:
        gate.stop()


if __name__ == "__main__":
    raise SystemExit(main())
