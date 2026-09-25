#!/usr/bin/python3.11 -I
# SPDX-License-Identifier: Apache-2.0
"""Guest side of the Docket clean-VM gate. Runs as root in a fresh Debian 12
guest with only the release artifacts, the build receipt and the shared AG
issuance vectors. Standard library plus /usr/bin/openssl; synthetic keys and
identities only. Writes result.json and one log per case."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import traceback
import uuid

HOME = pathlib.Path(sys.argv[1])
CANDIDATE = HOME / "candidate"
VECTORS = json.loads((HOME / "inputs" / "v2-vectors.json").read_text())
OUT = HOME / "gate"
TARBALL = "docket-0.1.0-linux-amd64.tar.gz"
TOP = "docket-0.1.0"
PREFIX = pathlib.Path("/opt/constellation/cohorts/gate/docket")
BIN = PREFIX / TOP / "bin"
DOCKET = BIN / "docket"
RESOLVER = BIN / "docket-local-standing-resolver"
ROOT = pathlib.Path("/var/lib/constellation/cohorts/gate")
PORTS = ROOT / "ports"
STATE = PORTS / "docket-state"
TRUST = PORTS / "docket-trust.json"
CONFIG = PORTS / "docket-standing-config.json"
LAUNCHER = PORTS / "docket-standing-launcher"
KEY = PORTS / "issuer.pk8"
FIXTURES = pathlib.Path("/opt/constellation/cohorts/gate/gate-fixtures")
EXECUTOR = FIXTURES / "trivial-executor"
RUNS = ROOT / "executor-runs"
ACCOUNT = "constellation"
OPERATOR = "cohort-gate-operator"
ISSUER = "cohort-gate-ag-issuer"
KEY_ID = "cohort-gate-ag-issuer-k1"
PY = "/usr/bin/python3.11"
WORK_SCHEMA = "gate.synthetic-exact-work/v1"
PREFIX_BYTES = base64.urlsafe_b64decode(VECTORS["signature_prefix_b64"] + "==")
RECEIPT = json.loads((CANDIDATE / "build-receipt.v1.json").read_text())
COMMIT = RECEIPT["source"]["commit"]

EXECUTOR_SOURCE = r'''#!/usr/bin/python3.11 -I
# Trivial synthetic executor for the Docket VM gate (docket.governed-executor-transport/v1).
import hashlib, json, os, sys, time
operation, config_path = sys.argv[1], sys.argv[2]
config = json.load(open(config_path))
state = config["state_dir"]
calls = os.path.join(state, "calls.log")
previous = open(calls).read().split() if os.path.exists(calls) else []
with open(calls, "a") as log:
    log.write(operation + "\n")
if operation == "plan-id":
    time.sleep(config.get("plan_id_delays", {}).get(str(previous.count("plan-id") + 1), 0))
    print(config["work"])
    sys.exit(0)
dispatch = json.load(sys.stdin)
effect = os.path.join(state, "effect.txt")
def answer(outcome, basis):
    receipt = "sha256:" + hashlib.sha256(basis.encode()).hexdigest()
    print(json.dumps({"attempt": dispatch["attempt"], "marker": dispatch["marker"],
                      "receipt": receipt, "outcome": outcome}))
if operation == "execute":
    fd = os.open(effect, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, ("synthetic effect for " + dispatch["attempt"] + "\n").encode())
    os.close(fd)
    answer("success", dispatch["attempt"] + ":" + dispatch["marker"] + ":executed")
elif operation == "reconcile":
    if os.path.exists(effect):
        answer("success", dispatch["attempt"] + ":" + dispatch["marker"] + ":executed")
    else:
        answer("indeterminate", dispatch["attempt"] + ":" + dispatch["marker"] + ":never-executed")
else:
    sys.exit(64)
'''

CASES = [
    ("I-01", "guest: Debian 12 with Debian /usr/bin/python3.11 and openssl; no Rust toolchain"),
    ("I-02", "artifact: sha256sum --check SHA256SUMS; receipt records a byte-equal reproduction"),
    ("I-03", "install: tarball members are safe; extracted as root:root; inner SHA256SUMS and receipt binary digests verify"),
    ("I-04", "identity: --version and --build-info of both binaries name component, 0.1.0 and the 40-hex source commit (release)"),
    ("I-05", "environment: no source tree or /data; only libc/libm/libgcc_s linked; no egress"),
    ("K-01", "setup: system account, fresh synthetic issuer key and trust file; guest signer reproduces AG vector v2-current byte for byte"),
    ("L-01", "standing-write-launcher --python-interpreter /usr/bin/python3.11: sealed create-once -IS launcher; no .pth hook runs; symlinked interpreter refused"),
    ("L-02", "launcher: refuses arguments and a mutated config; resolver answers through the launcher"),
    ("G-01", "standing-grant: exact tuple grant enrolls the operator; lifetime over 300 s and a second operator refused"),
    ("A-01", "accept: fresh signed v2 issuance with local standing executes the synthetic executor exactly once and settles"),
    ("A-02", "accept: re-delivery of the same issuance returns the same custody and never executes again"),
    ("N-01", "inspect: evidence-join fields (issuance with not-after, custody, settlement, executor binding)"),
    ("N-02", "standing-snapshot: fields join custody (execution standing, currentness) within the 30 s bound"),
    ("N-03", "reconcile: settled record read back without execute; attempt substitution refused; unknown issuance not_accepted"),
    ("S-01", "standing-revoke and standing-supersede append revisions; a second transition is refused"),
    ("R-01", "refusal: expired issuance (fresh and AG vector v2-current) is governed-issuance-expired; nothing persisted"),
    ("R-02", "refusal: v1 issuance for dispatch (alpha.6 retained vector and fresh v1) is governed-issuance-not-after-absent"),
    ("R-03", "refusal: extended not-after under the original signature / re-signed stale identity"),
    ("R-04", "refusal: not-after shape (v2 without, v1 with) is governed-issuance-not-after-shape"),
    ("R-05", "refusal: standing snapshot older than 30 s at custody (wall clock) is governed-execution-standing-snapshot-stale; nothing persisted; a prompt retry settles"),
    ("R-06", "bound after custody: snapshot older than 30 s before execute records typed indeterminate evidence; executor never executes"),
    ("R-07", "bound after custody: issuance not-after passes before execute records typed indeterminate evidence; executor never executes"),
    ("R-08", "refusal: revoked standing is governed-execution-standing-revoked"),
    ("R-09", "refusal: superseded standing is governed-execution-standing-superseded"),
    ("R-10", "refusal: absent standing (no grant for the tuple) fails closed at the local resolver"),
    ("R-11", "refusal: expired standing grant is governed-execution-standing-expired"),
    ("R-12", "refusal: untrusted issuer and substituted public key"),
    ("P-01", "packaging: a corrupted tarball fails its checksum"),
]


class CaseFail(Exception):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise CaseFail(message)


current_log: pathlib.Path | None = None


def log(text: str) -> None:
    if current_log is not None:
        with current_log.open("a") as handle:
            handle.write(text + "\n")


def run(argv: list[str], *, stdin: bytes | None = None, user: str | None = None,
        timeout: float = 180) -> subprocess.CompletedProcess[bytes]:
    full = (["runuser", "-u", user, "--"] if user else []) + [str(a) for a in argv]
    started = time.monotonic()
    done = subprocess.run(full, input=stdin, capture_output=True, timeout=timeout,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}, cwd="/")
    log(f"$ {' '.join(full)}\n# exit {done.returncode} in {time.monotonic() - started:.2f}s"
        + (f"\n--- stdout\n{done.stdout.decode(errors='replace')}" if done.stdout else "")
        + (f"\n--- stderr\n{done.stderr.decode(errors='replace')}" if done.stderr else ""))
    return done


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_domain(domain: str, payload: bytes) -> str:
    digest = hashlib.sha256(b"ag-ng\0digest\0v1\0")
    digest.update(len(domain).to_bytes(16, "big") + domain.encode())
    digest.update(len(payload).to_bytes(16, "big") + payload)
    return "sha256:" + digest.hexdigest()


def compact(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def identity(body: dict) -> str:
    schema = body["schema"]
    basis = {k: v for k, v in body.items() if k not in ("schema", "issuance")}
    return hash_domain(schema, compact(basis))


def openssl_sign(key_der: pathlib.Path, message: bytes) -> bytes:
    work = OUT / "sign-tmp"
    work.mkdir(exist_ok=True)
    (work / "message").write_bytes(message)
    done = run(["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", key_der,
                "-in", work / "message", "-out", work / "signature"])
    if done.returncode != 0:
        raise CaseFail("openssl signing failed")
    return (work / "signature").read_bytes()


def public_key(key_der: pathlib.Path) -> bytes:
    done = run(["openssl", "pkey", "-inform", "DER", "-in", key_der, "-pubout", "-outform", "DER"])
    expect(done.returncode == 0 and len(done.stdout) == 44, "public key extraction failed")
    return done.stdout[-32:]


def envelope(body: dict, *, key: pathlib.Path = KEY, principal: str = ISSUER, key_id: str = KEY_ID,
             signed_public: bytes | None = None) -> bytes:
    raw = compact(body)
    signature = openssl_sign(key, PREFIX_BYTES + raw)
    return compact({"schema": "ag.governed-loop.signed-issuance/v1", "body_b64": b64(raw),
                    "authentication": {"issuer_principal": principal, "signer_key_id": key_id,
                                       "signer_public_key": b64(signed_public or public_key(key)),
                                       "signature": b64(signature)}})


def rand_digest() -> str:
    return "sha256:" + os.urandom(32).hex()


def tuple_body(schema: str = "ag.governed-loop.issuance/v2", not_after: int | None = None) -> dict:
    body = {"schema": schema, "issuance": "", "key": {"campaign": rand_digest(), "occurrence": str(uuid.uuid4())},
            "program": rand_digest(), "proposal": rand_digest(), "work_schema": WORK_SCHEMA,
            "work": rand_digest(), "subject": rand_digest(), "scope": rand_digest(),
            "observation": rand_digest(), "standing_resolution": rand_digest(), "mandate": rand_digest(),
            "spend": rand_digest()}
    if not_after is not None:
        body["not_after_unix_ms"] = not_after
    body["issuance"] = identity(body)
    return body


def grant(body: dict, *, issued: int | None = None, expires: int | None = None,
          operator: str = OPERATOR) -> subprocess.CompletedProcess[bytes]:
    issued = now_ms() if issued is None else issued
    expires = issued + 240_000 if expires is None else expires
    return run([DOCKET, "governed-loop", "standing-grant", "--state", STATE, "--operator", operator,
                "--campaign", body["key"]["campaign"], "--occurrence", body["key"]["occurrence"],
                "--program", body["program"], "--work-schema", body["work_schema"], "--work", body["work"],
                "--subject", body["subject"], "--scope", body["scope"],
                "--issued-at-unix-ms", issued, "--expires-at-unix-ms", expires], user=ACCOUNT)


def granted_id(done: subprocess.CompletedProcess[bytes]) -> str:
    text = done.stdout.decode().strip()
    expect(done.returncode == 0 and text.startswith("execution_standing: sha256:"), f"grant failed: {text}")
    return text.split(": ", 1)[1]


def executor_config(name: str, work: str, delays: dict | None = None) -> pathlib.Path:
    state = RUNS / name
    state.mkdir(parents=True)
    config = state / "executor-config.json"
    config.write_text(json.dumps({"state_dir": str(state), "work": work, "plan_id_delays": delays or {}}))
    shutil.chown(state, ACCOUNT, ACCOUNT)
    shutil.chown(config, ACCOUNT, ACCOUNT)
    return config


def calls(config: pathlib.Path) -> list[str]:
    path = config.parent / "calls.log"
    return path.read_text().split() if path.exists() else []


def accept(env: bytes, config: pathlib.Path, *, trust: pathlib.Path = TRUST,
           timeout: float = 180) -> subprocess.CompletedProcess[bytes]:
    return run([DOCKET, "governed-loop", "accept", "--state", STATE, "--trust", trust,
                "--standing-resolver", LAUNCHER, "--executor", EXECUTOR, "--executor-config", config,
                "--require-local-standing-snapshot"], stdin=env, user=ACCOUNT, timeout=timeout)


def inspect(issuance: str) -> dict:
    done = run([DOCKET, "governed-loop", "inspect", "--state", STATE, "--issuance", issuance], user=ACCOUNT)
    expect(done.returncode == 0, "inspect failed")
    return json.loads(done.stdout)


def snapshot(issuance: str):
    done = run([DOCKET, "governed-loop", "standing-snapshot", "--state", STATE, "--issuance", issuance],
               user=ACCOUNT)
    expect(done.returncode == 0, "standing-snapshot failed")
    return json.loads(done.stdout)


def refusal(done: subprocess.CompletedProcess[bytes]) -> str:
    return done.stderr.decode(errors="replace").strip()


def refused_with(done, code: str, config: pathlib.Path | None, issuance: str | None) -> dict:
    text = refusal(done)
    expect(done.returncode != 0, f"expected refusal {code}, got exit 0: {done.stdout[:300]!r}")
    expect(text == f"refused/error: {code}", f"expected {code!r}, got {text!r}")
    observed = {"refusal": text}
    if config is not None:
        expect("execute" not in calls(config), "executor execute was invoked")
        expect(not (config.parent / "effect.txt").exists(), "effect exists")
        observed["executor_calls"] = calls(config)
    if issuance is not None:
        expect(inspect(issuance)["record"] is None, "a record was persisted")
        observed["persisted"] = False
    return observed


FACTS: dict = {}
SHARED: dict = {}


# ------------------------------------------------------------------ cases
def i01():
    release = pathlib.Path("/etc/os-release").read_text()
    expect('VERSION_ID="12"' in release and "debian" in release, "not Debian 12")
    py = run([PY, "--version"]).stdout.decode().strip()
    expect(os.path.realpath(PY) == PY and not os.path.islink(PY), "python3.11 is not a plain file")
    ossl = run(["openssl", "version"]).stdout.decode().strip()
    expect(ossl.startswith("OpenSSL 3."), "openssl 3 absent")
    for tool in ("cargo", "rustc", "rustup"):
        expect(shutil.which(tool) is None, f"{tool} present")
    FACTS.update({"python": py, "python_sha256": hashlib.sha256(pathlib.Path(PY).read_bytes()).hexdigest(),
                  "openssl": ossl, "kernel": os.uname().release})
    return {"python": py, "openssl": ossl, "rust_toolchain": "absent"}


def i02():
    done = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=CANDIDATE, capture_output=True)
    log(done.stdout.decode())
    expect(done.returncode == 0, "SHA256SUMS does not verify")
    expect(RECEIPT["reproduction"]["byte_equal"] is True and RECEIPT["reproduction"]["clean_builds"] == 2,
           "receipt lacks a byte-equal reproduction")
    tar_sha = hashlib.sha256((CANDIDATE / TARBALL).read_bytes()).hexdigest()
    expect(tar_sha == RECEIPT["artifacts"][TARBALL]["sha256"], "tarball digest differs from receipt")
    return {"tarball_sha256": tar_sha, "source_commit": COMMIT}


def i03():
    with tarfile.open(CANDIDATE / TARBALL) as archive:
        members = archive.getmembers()
        for member in members:
            name = member.name
            expect(name == TOP or name.startswith(TOP + "/"), f"member outside top: {name}")
            expect(not name.startswith("/") and ".." not in name.split("/"), f"unsafe path {name}")
            expect(member.isreg() or member.isdir(), f"non-regular member {name}")
            expect(member.mode & 0o7022 == 0, f"unsafe mode {oct(member.mode)} on {name}")
            expect(member.uid == 0 and member.gid == 0, f"non-root owner on {name}")
        PREFIX.mkdir(parents=True, mode=0o755)
        archive.extractall(PREFIX, numeric_owner=True)
    done = subprocess.run(["sha256sum", "--check", "--strict", "--quiet", "SHA256SUMS"], cwd=PREFIX / TOP,
                          capture_output=True)
    expect(done.returncode == 0, "inner SHA256SUMS does not verify")
    installed = {}
    for name, facts in RECEIPT["binaries"].items():
        path = BIN / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        stat = path.stat()
        expect(digest == facts["sha256"], f"{name} differs from receipt")
        expect(stat.st_uid == 0 and stat.st_gid == 0 and stat.st_mode & 0o777 == 0o755, f"{name} owner/mode")
        installed[name] = {"path": str(path), "sha256": digest}
    return {"members": len(members), "installed": installed}


def i04():
    observed = {}
    subprocess.run(["useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--no-create-home",
                    "--shell", "/usr/sbin/nologin", ACCOUNT], check=True)
    build_info_file = json.loads((PREFIX / TOP / "BUILD-INFO.json").read_text())
    expect(build_info_file["source_commit"] == COMMIT, "BUILD-INFO.json commit differs")
    for name in ("docket", "docket-local-standing-resolver"):
        version = run([BIN / name, "--version"], user=ACCOUNT)
        info = run([BIN / name, "--build-info"], user=ACCOUNT)
        expect(version.returncode == 0 and info.returncode == 0, f"{name} identity probe failed")
        line = version.stdout.decode().strip()
        expect(line == f"{name} 0.1.0 {COMMIT}", f"{name} --version is {line!r}")
        document = json.loads(info.stdout)
        expect(document == RECEIPT["binaries"][name]["build_info"], f"{name} --build-info differs from receipt")
        expect(document["cargo_profile"] == "release" and document["debug_assertions"] is False, "not release")
        expect(build_info_file["binaries"][name]["sha256"] == RECEIPT["binaries"][name]["sha256"], "BUILD-INFO sha")
        observed[name] = {"version": line, "build_info": document}
    return observed


def i05():
    found = [str(p) for base in ("/opt", "/home", "/root", "/srv") for p in pathlib.Path(base).rglob("Cargo.toml")]
    expect(not found, f"source tree present: {found}")
    expect(not os.path.exists("/data"), "/data exists")
    libs = {}
    for name in ("docket", "docket-local-standing-resolver"):
        text = run(["ldd", BIN / name]).stdout.decode()
        sonames = sorted(line.split()[0] for line in text.splitlines() if "=>" in line)
        expect(set(sonames) <= {"libc.so.6", "libm.so.6", "libgcc_s.so.1"}, f"{name} links {sonames}")
        libs[name] = sonames
    egress = "blocked"
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        egress = "open"
    except OSError:
        pass
    expect(egress == "blocked", "guest has egress")
    return {"linked": libs, "egress": egress}


def k01():
    for path, mode in ((ROOT.parent.parent, 0o711), (ROOT.parent, 0o711)):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
    ROOT.mkdir(mode=0o700)
    PORTS.mkdir(mode=0o700)
    RUNS.mkdir(mode=0o700)
    for path in (ROOT, PORTS, RUNS):
        shutil.chown(path, ACCOUNT, ACCOUNT)
    done = run(["openssl", "genpkey", "-algorithm", "Ed25519", "-outform", "DER", "-out", KEY])
    expect(done.returncode == 0, "genpkey failed")
    KEY.chmod(0o600)
    public = b64(public_key(KEY))
    TRUST.write_text(json.dumps({"issuers": [{"issuer_principal": ISSUER, "key_id": KEY_ID, "public_key": public}]}))
    CONFIG.write_text(compact({"operator": OPERATOR, "schema": "docket.governed-loop.local-standing-resolver-config/v1",
                               "state_database": str(STATE / "state.sqlite")}).decode())
    for path in (TRUST, CONFIG):
        path.chmod(0o600)
        shutil.chown(path, ACCOUNT, ACCOUNT)
    FIXTURES.mkdir(parents=True, mode=0o755)
    EXECUTOR.write_text(EXECUTOR_SOURCE)
    EXECUTOR.chmod(0o755)
    # Signer self-check against the AG-owned shared vector (conformance-only key).
    vector = VECTORS["vectors"][0]
    expect(vector["name"] == "v2-current", "vector order changed")
    conf_key = OUT / "conformance-key.der"
    # The corpus key is PKCS#8 v2 (OneAsymmetricKey with the public key), which
    # OpenSSL 3.0 does not load; re-wrap its 32-byte seed as PKCS#8 v1.
    v2 = unb64(VECTORS["test_signing_key_pkcs8_v2_b64"])
    expect(v2[:16] == bytes.fromhex("3053020101300506032b657004220420"), "unexpected corpus key encoding")
    conf_key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + v2[16:48])
    expect(public_key(conf_key) == v2[-32:], "re-wrapped corpus key has a different public key")
    body = json.loads(vector["body_jcs"])
    expect(compact(body).decode() == vector["body_jcs"], "guest JCS differs from the vector bytes")
    expect(identity(body) == vector["issuance"], "guest identity law differs from the vector")
    produced = json.loads(envelope(body, key=conf_key, principal="conformance.ag-issuer",
                                   key_id="conformance.ag-issuer.v2-vectors"))
    expect(produced == vector["envelope"], "guest signer does not reproduce the AG vector envelope")
    conf_trust = PORTS / "conformance-trust.json"
    conf_trust.write_text(json.dumps(VECTORS["trust"]))
    shutil.chown(conf_trust, ACCOUNT, ACCOUNT)
    return {"issuer_public_key": public, "trust": str(TRUST), "signer_reproduces_vector": vector["name"],
            "key": "fresh openssl genpkey Ed25519 (synthetic)"}


def l01():
    done = run([DOCKET, "governed-loop", "standing-write-launcher", "--resolver", RESOLVER, "--config", CONFIG,
                "--python-interpreter", PY, "--output", LAUNCHER], user=ACCOUNT)
    expect(done.returncode == 0, "launcher generation failed")
    stat = LAUNCHER.stat()
    expect(stat.st_mode & 0o777 == 0o700 and stat.st_uid != 0, "launcher mode/owner")
    text = LAUNCHER.read_text()
    expect(text.startswith(f"#!{PY} -IS\n"), "launcher shebang is not -IS")
    resolver_sha = hashlib.sha256(RESOLVER.read_bytes()).hexdigest()
    config_sha = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    expect(f'"{resolver_sha}"' in text and f'"{config_sha}"' in text, "launcher does not pin both digests")
    again = run([DOCKET, "governed-loop", "standing-write-launcher", "--resolver", RESOLVER, "--config", CONFIG,
                 "--python-interpreter", PY, "--output", LAUNCHER], user=ACCOUNT)
    expect(again.returncode != 0 and "local-standing-launcher-create" in refusal(again), "launcher not create-once")
    link = run([DOCKET, "governed-loop", "standing-write-launcher", "--resolver", RESOLVER, "--config", CONFIG,
                "--python-interpreter", "/usr/bin/python3", "--output", PORTS / "symlink-launcher"], user=ACCOUNT)
    expect(link.returncode != 0 and refusal(link) == "refused/error: local-standing-pin-file",
           "symlinked interpreter accepted")
    SHARED["launcher_sha256"] = hashlib.sha256(LAUNCHER.read_bytes()).hexdigest()
    # A system .pth hook fires under python3.11 -I but must not fire in the launcher (-IS).
    site_dir = pathlib.Path("/usr/local/lib/python3.11/dist-packages")
    site_dir.mkdir(parents=True, exist_ok=True)
    marker_dir = pathlib.Path("/run/docket-gate-pth")
    marker_dir.mkdir(mode=0o700, exist_ok=True)
    shutil.chown(marker_dir, ACCOUNT, ACCOUNT)
    marker = marker_dir / "marker"
    hook = site_dir / "zz-docket-gate-probe.pth"
    hook.write_text(f"import os; open({str(marker)!r}, 'a').write(str(os.getpid()) + chr(10))\n")
    try:
        marker.unlink(missing_ok=True)
        run([PY, "-I", "-c", "pass"], user=ACCOUNT)
        control = marker.exists()
        marker.unlink(missing_ok=True)
        probe = run([LAUNCHER], stdin=b'{"schema":"wrong"}', user=ACCOUNT)
        fired = marker.exists()
    finally:
        hook.unlink()
        marker.unlink(missing_ok=True)
    expect(control, "control: the .pth hook did not fire under -I, so the probe proves nothing")
    expect(not fired, "a system .pth hook ran inside the launcher")
    expect("local-standing-request" in refusal(probe), "launcher did not reach the resolver")
    return {"launcher": str(LAUNCHER), "launcher_sha256": SHARED["launcher_sha256"], "shebang": text.splitlines()[0],
            "pins": {"resolver": resolver_sha, "config": config_sha},
            "symlinked_interpreter": refusal(link),
            "pth_hook": {"fires_under_python3.11_-I": control, "fires_in_launcher": fired}}


def l02():
    args = run([LAUNCHER, "extra"], user=ACCOUNT)
    expect(args.returncode != 0 and "accepts no arguments" in refusal(args), "launcher accepted an argument")
    scratch = PORTS / "l02"
    scratch.mkdir()
    shutil.chown(scratch, ACCOUNT, ACCOUNT)
    config = scratch / "config.json"
    config.write_text(CONFIG.read_text())
    shutil.chown(config, ACCOUNT, ACCOUNT)
    probe = scratch / "launcher"
    done = run([DOCKET, "governed-loop", "standing-write-launcher", "--resolver", RESOLVER, "--config", config,
                "--python-interpreter", PY, "--output", probe], user=ACCOUNT)
    expect(done.returncode == 0, "probe launcher generation failed")
    with config.open("a") as handle:
        handle.write(" ")
    mutated = run([probe], stdin=b"{}", user=ACCOUNT)
    expect(mutated.returncode != 0 and "digest mismatch" in refusal(mutated), "mutated config accepted")
    # The real launcher reaches the resolver: a malformed request is refused by the resolver itself.
    reached = run([LAUNCHER], stdin=b'{"schema":"wrong"}', user=ACCOUNT)
    expect(reached.returncode != 0 and "local-standing-request" in refusal(reached), "resolver not reached")
    return {"argument": refusal(args), "mutated_config": refusal(mutated), "resolver_reached": refusal(reached)}


def g01():
    body = tuple_body(not_after=now_ms() + 150_000)
    body["issuance"] = identity(body)
    SHARED["a01_body"] = body
    issued = now_ms()
    over = grant(body, issued=issued, expires=issued + 300_001)
    expect(over.returncode != 0 and refusal(over) == "refused/error: local-standing-lifetime", "lifetime accepted")
    done = grant(body, issued=issued, expires=issued + 240_000)
    SHARED["a01_grant"] = granted_id(done)
    SHARED["a01_expires"] = issued + 240_000
    other = grant(tuple_body(not_after=now_ms() + 60_000), operator="another-operator")
    expect(other.returncode != 0 and refusal(other) == "refused/error: local-standing-operator-enrollment-mismatch",
           "second operator accepted")
    return {"execution_standing": SHARED["a01_grant"], "lifetime_over_300s": refusal(over),
            "second_operator": refusal(other)}


def a01():
    body = SHARED["a01_body"]
    env = envelope(body)
    SHARED["a01_env"] = env
    config = executor_config("a01", body["work"])
    SHARED["a01_config"] = config
    done = accept(env, config)
    expect(done.returncode == 0, f"accept failed: {refusal(done)}")
    custody = json.loads(done.stdout)
    SHARED["a01_custody"] = custody
    expect(custody["schema"] == "ag.governed-loop.docket-custody/v1" and custody["issuance"] == body["issuance"],
           "custody does not name the issuance")
    expect(calls(config) == ["plan-id", "plan-id", "execute"], f"executor calls {calls(config)}")
    effect = config.parent / "effect.txt"
    expect(effect.exists(), "no effect")
    return {"custody": custody, "executor_calls": calls(config), "effect": effect.read_text().strip()}


def a02():
    done = accept(SHARED["a01_env"], SHARED["a01_config"])
    expect(done.returncode == 0, "re-delivery refused")
    expect(json.loads(done.stdout) == SHARED["a01_custody"], "re-delivery custody differs")
    expect(calls(SHARED["a01_config"]).count("execute") == 1, "executed again")
    return {"same_custody": True, "executor_calls": calls(SHARED["a01_config"])}


def n01():
    body = SHARED["a01_body"]
    doc = inspect(body["issuance"])
    record = doc["record"]
    expect(doc["schema"] == "docket.governed-loop.inspection/v1", "inspection schema")
    expect(record["status"] == "settled", f"status {record['status']}")
    expect(record["issuance"]["schema"] == "ag.governed-loop.issuance/v2"
           and record["issuance"]["not_after_unix_ms"] == body["not_after_unix_ms"], "issuance not-after")
    expect(record["custody"] == SHARED["a01_custody"], "custody differs")
    settlement = record["settlement"]
    expect(settlement["outcome"] == "success" and settlement["attempt"] == record["custody"]["attempt"], "settlement")
    program = hash_domain("docket.governed-loop.executor-program/v1", EXECUTOR.read_bytes())
    expect(record["executor_program_digest"] == program, "executor program digest")
    expect(record["executor_plan"] == body["work"], "executor plan")
    expect(record["authentication"]["issuer_principal"] == ISSUER, "authentication")
    SHARED["n01"] = record
    return {"inspection_keys": sorted(doc), "record_keys": sorted(record), "custody_keys": sorted(record["custody"]),
            "settlement": settlement, "executor_binding": record["executor_binding"],
            "executor_program_digest": program, "not_after_unix_ms": record["issuance"]["not_after_unix_ms"]}


def n02():
    body = SHARED["a01_body"]
    snap = snapshot(body["issuance"])
    custody = SHARED["a01_custody"]
    expect(snap["schema"] == "docket.governed-loop.local-standing-snapshot/v1", "snapshot schema")
    expect(snap["issuance"] == body["issuance"] and snap["status"] == "current" and snap["revision"] == 1, "snapshot")
    expect(snap["execution_standing"] == SHARED["a01_grant"] == custody["execution_standing"], "standing join")
    expect(snap["currentness"] == custody["standing_currentness"], "currentness join")
    expect(snap["expires_at_unix_ms"] == SHARED["a01_expires"], "expiry")
    age = custody["accepted_at_unix_ms"] - snap["resolved_at_unix_ms"]
    expect(0 <= age <= 30_000, f"resolution to custody {age} ms")
    absent = snapshot(tuple_body(not_after=1)["issuance"])
    expect(absent is None, "snapshot for unknown issuance")
    return {"snapshot": snap, "resolution_to_custody_ms": age, "unknown_issuance": absent}


def n03():
    body = SHARED["a01_body"]
    custody = SHARED["a01_custody"]
    base = [DOCKET, "governed-loop"]
    tail = ["--state", STATE, "--executor", EXECUTOR, "--executor-config", SHARED["a01_config"]]
    done = run(base + ["reconcile-issuance"] + tail, stdin=compact({"issuance": body["issuance"]}), user=ACCOUNT)
    expect(done.returncode == 0, "reconcile-issuance failed")
    answer = json.loads(done.stdout)
    expect(answer["status"] == "settled" and answer["record"]["settlement"] == SHARED["n01"]["settlement"], "reconcile")
    good = run(base + ["reconcile-attempt"] + tail, stdin=compact({"issuance": body["issuance"],
                                                                    "attempt": custody["attempt"]}), user=ACCOUNT)
    expect(good.returncode == 0 and json.loads(good.stdout)["status"] == "settled", "reconcile-attempt")
    wrong = run(base + ["reconcile-attempt"] + tail, stdin=compact({"issuance": body["issuance"],
                                                                     "attempt": rand_digest()}), user=ACCOUNT)
    expect(refusal(wrong) == "refused/error: governed-reconciliation-attempt-substitution", "substitution")
    unknown = run(base + ["reconcile-issuance"] + tail, stdin=compact({"issuance": rand_digest()}), user=ACCOUNT)
    expect(unknown.returncode == 0 and json.loads(unknown.stdout) == {"status": "not_accepted"}, "unknown issuance")
    expect(calls(SHARED["a01_config"]).count("execute") == 1, "reconcile executed")
    return {"reconcile_issuance": answer["status"], "attempt_substitution": refusal(wrong),
            "unknown": json.loads(unknown.stdout), "executor_calls": calls(SHARED["a01_config"])}


def s01():
    observed = {}
    for action in ("standing-revoke", "standing-supersede"):
        body = tuple_body(not_after=now_ms() + 120_000)
        standing = granted_id(grant(body))
        done = run([DOCKET, "governed-loop", action, "--state", STATE, "--execution-standing", standing,
                    "--at-unix-ms", now_ms()], user=ACCOUNT)
        expect(done.returncode == 0 and done.stdout.decode().strip() == "revision: 2", f"{action} failed")
        again = run([DOCKET, "governed-loop", action, "--state", STATE, "--execution-standing", standing,
                     "--at-unix-ms", now_ms()], user=ACCOUNT)
        expect(refusal(again) == "refused/error: local-standing-not-current", f"second {action} accepted")
        SHARED[action] = body
        observed[action] = {"execution_standing": standing, "revision": 2, "second_transition": refusal(again)}
    return observed


def r01():
    body = tuple_body(not_after=now_ms() - 1_000)
    granted_id(grant(body))
    config = executor_config("r01", body["work"])
    fresh = refused_with(accept(envelope(body), config), "governed-issuance-expired", config, body["issuance"])
    vector = VECTORS["vectors"][0]
    vector_config = executor_config("r01-vector", json.loads(vector["body_jcs"])["work"])
    ag = refused_with(accept(compact(vector["envelope"]), vector_config, trust=PORTS / "conformance-trust.json"),
                      "governed-issuance-expired", vector_config, vector["issuance"])
    return {"fresh": fresh, "ag_vector_v2_current": ag}


def r02():
    vector = VECTORS["vectors"][1]
    expect(vector["name"] == "v1-alpha6-retained", "vector order changed")
    config = executor_config("r02-vector", json.loads(vector["body_jcs"])["work"])
    alpha6 = refused_with(accept(compact(vector["envelope"]), config, trust=PORTS / "conformance-trust.json"),
                          "governed-issuance-not-after-absent", config, vector["issuance"])
    body = tuple_body(schema="ag.governed-loop.issuance/v1")
    granted_id(grant(body))
    fresh_config = executor_config("r02", body["work"])
    fresh = refused_with(accept(envelope(body), fresh_config), "governed-issuance-not-after-absent",
                         fresh_config, body["issuance"])
    return {"alpha6_retained_v1": alpha6, "fresh_v1": fresh}


def r03():
    body = tuple_body(not_after=now_ms() + 120_000)
    granted_id(grant(body))
    config = executor_config("r03", body["work"])
    original = json.loads(envelope(body))
    extended = dict(body, not_after_unix_ms=body["not_after_unix_ms"] + 3_600_000)
    under_original = dict(original, body_b64=b64(compact(extended)))
    a = refused_with(accept(compact(under_original), config), "governed-issuance-signature-invalid", config,
                     body["issuance"])
    b = refused_with(accept(envelope(extended), config), "governed-issuance-identity-mismatch", config,
                     body["issuance"])
    vectors = {}
    for index, code in ((2, "governed-issuance-signature-invalid"), (3, "governed-issuance-identity-mismatch")):
        vector = VECTORS["vectors"][index]
        vconfig = executor_config(f"r03-v{index}", json.loads(vector["body_jcs"])["work"])
        vectors[vector["name"]] = refused_with(accept(compact(vector["envelope"]), vconfig,
                                                      trust=PORTS / "conformance-trust.json"), code, vconfig, None)
    return {"extended_under_original_signature": a, "extended_resigned_stale_identity": b, "vectors": vectors}


def r04():
    observed = {}
    for index in (4, 5):
        vector = VECTORS["vectors"][index]
        config = executor_config(f"r04-v{index}", json.loads(vector["body_jcs"])["work"])
        observed[vector["name"]] = refused_with(accept(compact(vector["envelope"]), config,
                                                       trust=PORTS / "conformance-trust.json"),
                                                "governed-issuance-not-after-shape", config, None)
    return observed


def r05():
    body = tuple_body(not_after=now_ms() + 200_000)
    granted_id(grant(body))
    slow = executor_config("r05-slow", body["work"], {"1": 31})
    env = envelope(body)
    started = now_ms()
    refused = refused_with(accept(env, slow, timeout=240), "governed-execution-standing-snapshot-stale", slow,
                           body["issuance"])
    refused["elapsed_ms"] = now_ms() - started
    fast = executor_config("r05-fast", body["work"])
    retry = accept(env, fast)
    expect(retry.returncode == 0, f"retry refused: {refusal(retry)}")
    expect(inspect(body["issuance"])["record"]["status"] == "settled" and calls(fast).count("execute") == 1,
           "retry did not settle once")
    return {"stale": refused, "retry_after_refusal": "settled once (nothing was persisted or consumed)"}


def after_custody(name: str, not_after_in: int, delay: int, domain: str, evidence_basis) -> dict:
    body = tuple_body(not_after=now_ms() + not_after_in)
    granted_id(grant(body))
    config = executor_config(name, body["work"], {"2": delay})
    done = accept(envelope(body), config, timeout=240)
    expect(done.returncode == 0, f"accept after custody should return custody: {refusal(done)}")
    custody = json.loads(done.stdout)
    record = inspect(body["issuance"])["record"]
    expect(record["status"] == "indeterminate", f"status {record['status']}")
    expected = hash_domain(domain, evidence_basis(body, custody).encode())
    expect(record["indeterminate"]["evidence"] == expected, "evidence digest differs")
    expect("execute" not in calls(config) and not (config.parent / "effect.txt").exists(), "executor executed")
    rec = run([DOCKET, "governed-loop", "reconcile-issuance", "--state", STATE, "--executor", EXECUTOR,
               "--executor-config", config], stdin=compact({"issuance": body["issuance"]}), user=ACCOUNT)
    expect(rec.returncode == 0 and json.loads(rec.stdout)["status"] == "indeterminate", "reconcile")
    expect("execute" not in calls(config), "reconcile executed")
    return {"custody_attempt": custody["attempt"], "status": "indeterminate", "evidence": expected,
            "evidence_domain": domain, "executor_calls": calls(config), "reconcile": "indeterminate, no execute"}


def r06():
    return after_custody("r06", 200_000, 31, "docket.governed-loop.standing-snapshot-exceeded-before-execute/v1",
                         lambda body, custody: f"{body['issuance']}\0{custody['standing_currentness']}")


def r07():
    return after_custody("r07", 20_000, 25, "docket.governed-loop.issuance-expired-before-execute/v1",
                         lambda body, custody: f"{body['issuance']}\0{body['not_after_unix_ms']}")


def transitioned(action: str, code: str) -> dict:
    body = SHARED[action]
    config = executor_config(f"r-{action}", body["work"])
    return refused_with(accept(envelope(body), config), code, config, body["issuance"])


def r08():
    return transitioned("standing-revoke", "governed-execution-standing-revoked")


def r09():
    return transitioned("standing-supersede", "governed-execution-standing-superseded")


def r10():
    body = tuple_body(not_after=now_ms() + 120_000)
    config = executor_config("r10", body["work"])
    done = accept(envelope(body), config)
    text = refusal(done)
    expect(done.returncode != 0 and text.endswith("local-standing-absent"), f"absent: {text!r}")
    expect("execute" not in calls(config) and inspect(body["issuance"])["record"] is None, "persisted or executed")
    return {"refusal": text, "persisted": False, "executor_calls": calls(config)}


def r11():
    body = tuple_body(not_after=now_ms() + 120_000)
    issued = now_ms() - 5_000
    granted_id(grant(body, issued=issued, expires=issued + 8_000))
    time.sleep(4)
    config = executor_config("r11", body["work"])
    return refused_with(accept(envelope(body), config), "governed-execution-standing-expired", config,
                        body["issuance"])


def r12():
    body = tuple_body(not_after=now_ms() + 120_000)
    granted_id(grant(body))
    config = executor_config("r12", body["work"])
    other = OUT / "other-key.der"
    run(["openssl", "genpkey", "-algorithm", "Ed25519", "-outform", "DER", "-out", other])
    untrusted = refused_with(accept(envelope(body, key=other, principal="someone-else"), config),
                             "governed-issuance-untrusted-issuer", config, body["issuance"])
    substituted = refused_with(accept(envelope(body, key=other), config),
                               "governed-issuance-public-key-substitution", config, body["issuance"])
    trusted_key = public_key(KEY)
    forged = refused_with(accept(envelope(body, key=other, signed_public=trusted_key), config),
                          "governed-issuance-signature-invalid", config, body["issuance"])
    return {"untrusted_issuer": untrusted, "public_key_substitution": substituted, "forged_signature": forged}


def p01():
    work = OUT / "p01"
    work.mkdir()
    shutil.copy(CANDIDATE / TARBALL, work / TARBALL)
    shutil.copy(CANDIDATE / "SHA256SUMS", work / "SHA256SUMS")
    shutil.copy(CANDIDATE / "build-receipt.v1.json", work / "build-receipt.v1.json")
    with (work / TARBALL).open("r+b") as handle:
        handle.seek(4096)
        byte = handle.read(1)
        handle.seek(4096)
        handle.write(bytes([byte[0] ^ 0xFF]))
    done = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=work, capture_output=True)
    expect(done.returncode != 0, "corrupted tarball verified")
    return {"sha256sum_exit": done.returncode, "output": done.stdout.decode().strip()}


FUNCTIONS = {"I-01": i01, "I-02": i02, "I-03": i03, "I-04": i04, "I-05": i05, "K-01": k01, "L-01": l01,
             "L-02": l02, "G-01": g01, "A-01": a01, "A-02": a02, "N-01": n01, "N-02": n02, "N-03": n03,
             "S-01": s01, "R-01": r01, "R-02": r02, "R-03": r03, "R-04": r04, "R-05": r05, "R-06": r06,
             "R-07": r07, "R-08": r08, "R-09": r09, "R-10": r10, "R-11": r11, "R-12": r12, "P-01": p01}


def main() -> int:
    global current_log
    (OUT / "cases").mkdir(parents=True, exist_ok=True)
    results = []
    for cid, title in CASES:
        current_log = OUT / "cases" / f"{cid}.log"
        current_log.write_text(f"# {cid}: {title}\n")
        started = time.monotonic()
        try:
            observed = FUNCTIONS[cid]() or {}
            result = {"id": cid, "title": title, "outcome": "PASS", "observed": observed}
        except CaseFail as error:
            result = {"id": cid, "title": title, "outcome": "FAIL", "error": str(error)}
        except Exception as error:  # noqa: BLE001
            result = {"id": cid, "title": title, "outcome": "FAIL", "error": f"{type(error).__name__}: {error}",
                      "trace": traceback.format_exc()[-3000:]}
        result["seconds"] = round(time.monotonic() - started, 2)
        log(f"# outcome {result['outcome']}")
        print(f"{cid} {result['outcome']} {result.get('error', '')}", flush=True)
        results.append(result)
        (OUT / "result.json").write_text(json.dumps({"facts": FACTS, "cases": results}, indent=2, sort_keys=True))
    return 0 if all(r["outcome"] == "PASS" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
