#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent check of a finished demo run. Standard library plus openssl.

Usage: check.py RUN_DIR [--docket PATH]

It shares no code with the demo. From the retained files alone it re-derives:
  - that the signed authorization verifies and names exactly the refund plan;
  - Docket's attempt and marker identities, and every settlement digest;
  - what really happened, from the provider's own ledger and access log;
  - the disposition that evidence supports, by the published rule;
and compares these with what Docket recorded, what the agent claimed and what
the observer saw. With --docket it also re-reads Docket's store (read-only) and
requires it to equal the retained copies.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

FAILURES: list[str] = []


def check(ok: bool, text: str) -> None:
    print(("  ok    " if ok else "  FAIL  ") + text)
    if not ok:
        FAILURES.append(text)


def load(path: pathlib.Path):
    return json.loads(path.read_text())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_domain(domain: str, payload: bytes) -> str:
    digest = hashlib.sha256(b"ag-ng\0digest\0v1\0")
    digest.update(len(domain).to_bytes(16, "big") + domain.encode())
    digest.update(len(payload).to_bytes(16, "big") + payload)
    return "sha256:" + digest.hexdigest()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_signature(public_raw: bytes, message: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / "pub.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + public_raw)
        (tmp / "msg").write_bytes(message)
        (tmp / "sig").write_bytes(signature)
        done = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey",
                               str(tmp / "pub.der"), "-rawin", "-in", str(tmp / "msg"), "-sigfile",
                               str(tmp / "sig")], capture_output=True)
        return done.returncode == 0


def jsonl(path: pathlib.Path) -> list:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def scenario(run: pathlib.Path, name: str, docket: str | None, repo_vectors: pathlib.Path) -> dict:
    home = run / name
    print(f"\n{name}")
    task = load(home / "task.json")
    plan = task["plan"]
    envelope = load(home / "authorization.json")
    trust = load(run / "authority" / "trust.json")["issuers"][0]
    body_bytes = unb64(envelope["body_b64"])
    body = json.loads(body_bytes)
    prefix = unb64(load(repo_vectors)["signature_prefix_b64"])
    auth = envelope["authentication"]

    # 1. The authorization and the effect it names.
    check(auth["signer_public_key"] == trust["public_key"] and verify_signature(
        unb64(trust["public_key"]), prefix + body_bytes, unb64(auth["signature"])),
        "authorization signature verifies against the trusted demo key")
    basis = {k: v for k, v in body.items() if k not in ("schema", "issuance")}
    check(body["issuance"] == hash_domain(body["schema"], canonical(basis)),
          "authorization identity recomputes (" + body["schema"] + ")")
    check(body["work"] == sha(canonical(plan)), "authorization names exactly this refund plan")
    issuance = body["issuance"]
    attempt = hash_domain("ag.governed-loop.docket-attempt/v1", json.dumps(issuance).encode())
    marker = hash_domain("docket.governed-loop.executor-marker/v1", attempt.encode())
    request = {"schema": plan["schema"], "order": plan["order"], "amount_cents": plan["amount_cents"],
               "currency": plan["currency"], "apply_before_unix_ms": plan["apply_before_unix_ms"],
               "idempotency_key": marker}
    request_id = sha(canonical(request))
    custody = load(home / "accept-response.json")
    check(custody["attempt"] == attempt and custody["executor_marker"] == marker,
          "Docket's attempt and marker identities recompute from the authorization")
    check(load(home / "redelivery-response.json") == custody, "re-sending the authorization returned the same attempt")

    # 2. The agent's claim.
    claim = load(home / "agent-claim.json")
    check(claim["message"].startswith("Done.") and claim["basis"] == "command exited 0",
          f"agent claimed success because its command exited 0")

    # 3. The ambiguity and the intermediate disposition.
    first = load(home / "docket-after-accept.json")["record"]
    check(first["status"] == "indeterminate" and first["settlement"] is None,
          "Docket's first disposition: indeterminate, no settlement")
    no_reply = list((home / "executor-journal").glob("*.no-reply.json"))
    reservations = list((home / "executor-journal").glob("*.reservation.json"))
    check(len(reservations) == 1 and len(no_reply) == 1, "the worker sent once and holds a no-reply record")
    evidence_bytes = no_reply[0].read_bytes()
    check(first["indeterminate"]["evidence"] == sha(evidence_bytes),
          "Docket's indeterminate evidence is the worker's no-reply record")
    check(first["indeterminate"]["reconciliation"] == hash_domain(
        "docket.governed-loop.reconciliation/v1",
        f"{issuance}:{attempt}:{first['indeterminate']['evidence']}".encode()),
        "indeterminate reconciliation digest recomputes")
    check(load(no_reply[0].parent / no_reply[0].name)["request_id"] == request_id,
          "the no-reply record is for this exact provider request")

    # 4. What really happened, from the provider's own records only.
    ledger = [e for e in jsonl(run / "provider" / "ledger.jsonl") if e["request_id"] == request_id]
    for entry in ledger:
        check(entry["request"] == request and sha(canonical(entry["request"])) == request_id,
              "provider ledger entry is exactly this request")
    access = [e for e in jsonl(run / "provider" / "access.log") if e["request_id"] == request_id]
    applies = [e for e in access if e["op"] == "apply"]
    lookups = [e for e in access if e["op"] == "lookup"]
    check(len(applies) <= 1, f"provider received this request {len(applies)} time(s) (never twice)")
    if ledger:
        truth = "success"
        why = f"the ledger has refund {ledger[0]['refund_id']}"
    elif lookups and lookups[-1]["at_unix_ms"] >= plan["apply_before_unix_ms"]:
        truth = "failure"
        why = "no such refund in the ledger; deadline passed before the last lookup"
    else:
        truth = "indeterminate"
        why = "no such refund in the ledger; it could still apply"
    print(f"        from the provider's records: {truth} ({why})")

    # 5. The independent observation(s).
    observations = {}
    for path in (home / "observations").glob("*.json"):
        data = path.read_bytes()
        check(path.name == hashlib.sha256(data).hexdigest() + ".json", f"observation {path.name[:12]} is intact")
        observations[sha(data)] = json.loads(data)
    forbidden = [claim["message"], "example.agent-claim/v1", sha(evidence_bytes), "example.refund-executor.no-reply/v1"]
    for digest, seen in observations.items():
        answer = seen["provider_answer"]
        check(seen["request"] == request and answer["request_id"] == request_id,
              f"observation {digest[7:19]} asked about exactly this request")
        text = json.dumps(seen)
        check(not any(item in text for item in forbidden),
              f"observation {digest[7:19]} contains nothing from the agent's claim or the worker's journal")
        state_ok = (answer["state"] == "committed") == bool(ledger and ledger[0]["committed_at_unix_ms"] <= answer["provider_now_unix_ms"])
        check(state_ok, f"observation {digest[7:19]} agrees with the provider ledger ({answer['state']})")
    reconciles = sorted(home.glob("reconcile-*.json"))
    for path in reconciles[:-1]:
        early = load(path)
        check(early["status"] == "indeterminate",
              f"{path.name}: evidence that the refund could still apply left the attempt indeterminate")

    # 6. The final disposition.
    final = load(home / "docket-final.json")["record"]
    settlement = final["settlement"]
    outcome = settlement["outcome"] if settlement else final["status"]
    check(outcome == truth, f"Docket's final disposition ({outcome}) equals the re-derived one ({truth})")
    if settlement:
        check(settlement["receipt"] in observations,
              "the settlement's receipt is an observer document, not the worker's or the agent's")
        check(settlement["settlement"] == hash_domain(
            "docket.governed-loop.settlement/v1",
            f"{issuance}:{attempt}:{settlement['receipt']}:{settlement['outcome']}".encode()),
            "settlement digest recomputes")
        check(final["indeterminate"] == first["indeterminate"], "the earlier indeterminate evidence is retained")
    program = hash_domain("docket.governed-loop.executor-program/v1",
                          (pathlib.Path(__file__).resolve().parent / "bin" / "refund-executor").read_bytes())
    check(final["executor_program_digest"] == program, "the executor Docket ran is this repository's bin/refund-executor")
    if docket:
        live = subprocess.run([docket, "governed-loop", "inspect", "--state", str(run / "docket-state"),
                               "--issuance", issuance], capture_output=True, check=True)
        check(json.loads(live.stdout)["record"] == final, "Docket's store, re-read now, equals the retained record")
    network = jsonl(home / "network.log")
    print("        context only (not used above): network log says "
          + "; ".join(e["event"] for e in network))
    return {"claim": claim, "outcome": outcome}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=pathlib.Path)
    parser.add_argument("--docket")
    args = parser.parse_args()
    vectors = pathlib.Path(__file__).resolve().parents[2] / "conformance/ag-governed-loop-issuance/v2-vectors.json"
    results = [scenario(args.run, name, args.docket, vectors) for name in ("A-lost-reply", "B-lost-request")]
    print("\nacross runs")
    check(all(r["claim"]["basis"] == "command exited 0" for r in results)
          and len({r["outcome"] for r in results}) == 2,
          "the agent said done both times; the final dispositions differ (" +
          ", ".join(r["outcome"] for r in results) + ")")
    print(f"\n{'PASS' if not FAILURES else 'FAIL'}: {len(FAILURES)} failed check(s)")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
