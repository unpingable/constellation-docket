#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Indeterminate-effect demo driver: runs two refunds through Docket and narrates.

Usage: demo.py --docket-bin DIR --out DIR

Everything the narration states is read back from a record written by some
other program (Docket's store, the agent's claim, the executor's journal, the
observer's document, the network log). The driver chooses only which network
fault to inject. It never tells Docket, the executor or the observer what
the answer should be.
"""
import argparse
import json
import os
import pathlib
import platform
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

import authority_standin as authority

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE / "bin"
WORK_SCHEMA = "example.refund-request/v1"
OPERATOR = "demo-operator"
ISSUER = "demo-authority"
KEY_ID = "demo-authority-k1"
APPLY_WINDOW_MS = 8_000


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def clock(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%H:%M:%S")


def short(path: pathlib.Path) -> str:
    relative = os.path.relpath(path)
    return relative if len(relative) < len(str(path)) else str(path)


def dollars(cents: int) -> str:
    return f"${cents // 100}.{cents % 100:02d}"


class Demo:
    def __init__(self, docket_bin: pathlib.Path, out: pathlib.Path):
        self.docket = docket_bin / "docket"
        self.resolver = docket_bin / "docket-local-standing-resolver"
        self.out = out
        self.started = time.monotonic()
        self.children: list[subprocess.Popen] = []

    # -- output -------------------------------------------------------------
    def say(self, text: str = "") -> None:
        print(text, flush=True)

    def beat(self, number: int, title: str, text: str) -> None:
        stamp = f"[{time.monotonic() - self.started:5.1f}s]"
        lines = text.split("\n")
        self.say(f"{stamp} {number}. {title}")
        for line in lines:
            self.say(f"          {line}")

    # -- processes ----------------------------------------------------------
    def run(self, argv, *, stdin: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
        done = subprocess.run([str(a) for a in argv], input=stdin, capture_output=True)
        if check and done.returncode != 0:
            raise SystemExit(f"command failed ({done.returncode}): {' '.join(map(str, argv))}\n"
                             f"{done.stderr.decode(errors='replace')}")
        return done

    def spawn(self, argv, port_file: pathlib.Path) -> int:
        child = subprocess.Popen([str(a) for a in argv], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(child)
        for _ in range(200):
            if port_file.exists() and port_file.read_text():
                return int(port_file.read_text())
            if child.poll() is not None:
                raise SystemExit(f"{argv[0]} exited early")
            time.sleep(0.05)
        raise SystemExit(f"{argv[0]} did not start")

    def stop(self) -> None:
        for child in self.children:
            child.terminate()
        for child in self.children:
            child.wait(timeout=10)

    def write(self, path: pathlib.Path, value) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def inspect(self, issuance: str) -> dict:
        return json.loads(self.run([self.docket, "governed-loop", "inspect", "--state", self.state,
                                    "--issuance", issuance]).stdout)

    # -- setup --------------------------------------------------------------
    def setup(self) -> None:
        self.out.mkdir(parents=True, exist_ok=True)
        if any(p.name != "transcript.txt" for p in self.out.iterdir()):
            raise SystemExit(f"{self.out} is not empty")
        interpreter = os.path.realpath(sys.executable)
        version = self.run([self.docket, "--version"]).stdout.decode().strip()
        self.write(self.out / "run.json", {
            "docket_version": version,
            "docket_build_info": json.loads(self.run([self.docket, "--build-info"]).stdout),
            "python": platform.python_version(), "python_interpreter": interpreter,
            "openssl": self.run(["openssl", "version"]).stdout.decode().strip(),
            "kernel": platform.release(), "started_at_unix_ms": now_ms()})
        keys = self.out / "authority"
        keys.mkdir()
        vector_sha = authority.self_check(keys)
        self.key = keys / "issuer-private.der"
        authority.generate_key(self.key)
        self.trust = keys / "trust.json"
        self.write(self.trust, {"issuers": [{"issuer_principal": ISSUER, "key_id": KEY_ID,
                                             "public_key": authority.b64(authority.public_key(self.key))}]})
        self.write(keys / "self-check.json", {"reproduced_vector": "v2-current",
                                              "vector_file_sha256": vector_sha})
        # Docket's local execution standing: config, sealed launcher, state.
        self.state = self.out / "docket-state"
        config = self.out / "docket-standing-config.json"
        config.write_text(authority.compact({"operator": OPERATOR,
                                             "schema": "docket.governed-loop.local-standing-resolver-config/v1",
                                             "state_database": str(self.state / "state.sqlite")}).decode())
        self.launcher = self.out / "docket-standing-launcher"
        self.run([self.docket, "governed-loop", "standing-write-launcher", "--resolver", self.resolver,
                  "--config", config, "--python-interpreter", interpreter, "--output", self.launcher])
        provider_dir = self.out / "provider"
        self.provider_port = self.spawn([BIN / "provider", "--state", provider_dir,
                                         "--port-file", provider_dir / "port"], provider_dir / "port")
        self.say(f"Docket, which keeps custody of each attempt and its result: {version}")
        self.say(f"Authorization signer: stand-in, reproduces AG's published test vector (sha256 {vector_sha[:12]}...)")
        self.say(f"Provider: stand-in payment service on 127.0.0.1:{self.provider_port}, ledger {provider_dir.name}/ledger.jsonl")
        self.say(f"Receipts: {short(self.out)}")

    # -- one scenario -------------------------------------------------------
    def scenario(self, name: str, title: str, fault: str, order: str, cents: int) -> None:
        home = self.out / name
        home.mkdir()
        self.say()
        self.say(f"=== {title} ===")
        link_port = self.spawn([BIN / "flaky-link", "--mode", fault, "--upstream-port-file",
                                self.out / "provider" / "port", "--port-file", home / "link-port",
                                "--log", home / "network.log"], home / "link-port")
        task = f"Refund {dollars(cents)} for order {order}"
        plan = {"schema": WORK_SCHEMA, "order": order, "amount_cents": cents, "currency": "USD",
                "apply_before_unix_ms": now_ms() + APPLY_WINDOW_MS}
        executor_config = home / "executor-config.json"
        self.write(executor_config, {
            "plan": plan, "reply_timeout_s": 5,
            "send_url": f"http://127.0.0.1:{link_port}",
            "observer": str(BIN / "observe"),
            "observer_provider_url": f"http://127.0.0.1:{self.provider_port}",
            "journal_dir": str(home / "executor-journal"),
            "observations_dir": str(home / "observations")})
        plan_id = self.run([BIN / "refund-executor", "plan-id", executor_config]).stdout.decode().strip()
        self.write(home / "task.json", {"task": task, "plan": plan, "plan_id": plan_id})

        # The authorizing service's signed work order for exactly this plan.
        body = {"schema": "ag.governed-loop.issuance/v2", "issuance": "",
                "key": {"campaign": authority.hash_domain("example.campaign/v1", b"indeterminate-effect-demo"),
                        "occurrence": str(uuid.uuid4())},
                "program": authority.hash_domain("example.program/v1", b"refunds"),
                "proposal": authority.hash_domain("example.proposal/v1", task.encode()),
                "work_schema": WORK_SCHEMA, "work": plan_id,
                "subject": authority.hash_domain("example.subject/v1", f"order:{order}".encode()),
                "scope": authority.hash_domain("example.scope/v1", b"refund-once"),
                "observation": authority.hash_domain("example.observation/v1", os.urandom(16)),
                "standing_resolution": authority.hash_domain("example.standing/v1", os.urandom(16)),
                "mandate": authority.hash_domain("example.mandate/v1", os.urandom(16)),
                "spend": authority.hash_domain("example.spend/v1", os.urandom(16)),
                "not_after_unix_ms": now_ms() + 120_000}
        body["issuance"] = authority.identity(body)
        envelope = authority.envelope(body, self.key, ISSUER, KEY_ID)
        envelope_file = home / "authorization.json"
        envelope_file.write_bytes(authority.compact(envelope))
        issued = now_ms()
        grant = self.run([self.docket, "governed-loop", "standing-grant", "--state", self.state,
                          "--operator", OPERATOR, "--campaign", body["key"]["campaign"],
                          "--occurrence", body["key"]["occurrence"], "--program", body["program"],
                          "--work-schema", WORK_SCHEMA, "--work", plan_id, "--subject", body["subject"],
                          "--scope", body["scope"], "--issued-at-unix-ms", issued,
                          "--expires-at-unix-ms", issued + 240_000]).stdout.decode()
        (home / "standing-grant.txt").write_text(grant)

        accept = [self.docket, "governed-loop", "accept", "--state", self.state, "--trust", self.trust,
                  "--standing-resolver", self.launcher, "--executor", BIN / "refund-executor",
                  "--executor-config", executor_config, "--require-local-standing-snapshot"]
        self.beat(1, "Effect attempted",
                  f"An agent is asked to: {task}.\n"
                  f"The request must apply at the provider before {clock(plan['apply_before_unix_ms'])} UTC or not at all.\n"
                  f"A signed authorization for exactly this request goes to Docket, which sends it once.")
        agent = self.run([BIN / "agent", "--task", task, "--claim", home / "agent-claim.json",
                          "--stdin", envelope_file, "--stdout", home / "accept-response.json", "--",
                          *accept], check=False)
        claim = json.loads((home / "agent-claim.json").read_text())
        journal = sorted((home / "executor-journal").glob("*.json"))
        no_reply = [p for p in journal if p.name.endswith(".no-reply.json")]
        if no_reply:
            evidence = json.loads(no_reply[0].read_text())
            waited = (evidence["gave_up_at_unix_ms"] - evidence["sent_at_unix_ms"]) / 1000
            self.beat(2, "Outcome ambiguous",
                      f"The worker sent the request; the connection closed with no reply after {waited:.1f}s\n"
                      f"({evidence['error'].split(':')[0]}). It cannot tell whether the refund happened,\n"
                      f"and says so: outcome \"indeterminate\".")
        else:
            self.beat(2, "Outcome ambiguous", "The worker received a reply: " + ", ".join(p.name for p in journal))
        self.beat(3, "Agent says success",
                  f"agent: \"{claim['message']}\"\n"
                  f"Its evidence: {claim['basis']}.")
        after = self.inspect(body["issuance"])
        self.write(home / "docket-after-accept.json", after)
        record = after["record"]
        text = (f"Docket's record for this attempt: {record['status'].upper()}.\n"
                f"Settlement: {'none' if record['settlement'] is None else record['settlement']['outcome']}. "
                f"Not success, not failure.\n"
                f"The exit code 0 the agent saw only meant that Docket took custody.")
        # Asking again must not resend the refund.
        again = self.run(accept, stdin=envelope_file.read_bytes(), check=False)
        (home / "redelivery-response.json").write_bytes(again.stdout)
        same = again.returncode == 0 and json.loads(again.stdout) == json.loads((home / "accept-response.json").read_text())
        reservations = len(list((home / "executor-journal").glob("*.reservation.json")))
        text += (f"\nSending the same authorization again returns {'the same' if same else 'a DIFFERENT'} attempt.\n"
                 f"The worker has sent {reservations} request(s) in total.")
        self.beat(4, "System: INDETERMINATE" if record["status"] == "indeterminate"
                  else f"System: {record['status'].upper()}", text)

        attempt = record["custody"]["attempt"]
        step = 0
        while True:
            step += 1
            response = self.run([self.docket, "governed-loop", "reconcile-attempt", "--state", self.state,
                                 "--executor", BIN / "refund-executor", "--executor-config", executor_config],
                                stdin=authority.compact({"issuance": body["issuance"], "attempt": attempt}))
            reconciled = json.loads(response.stdout)
            self.write(home / f"reconcile-{step}.json", reconciled)
            observations = sorted((home / "observations").glob("*.json"), key=lambda p: p.stat().st_mtime_ns)
            seen = json.loads(observations[-1].read_text())
            answer = seen["provider_answer"]
            if answer["state"] == "committed":
                heard = (f"provider: this exact request is COMMITTED, as refund "
                         f"{answer['entry']['refund_id']} at {clock(answer['entry']['committed_at_unix_ms'])} UTC.")
            elif answer["can_still_apply"]:
                heard = (f"provider: no such refund yet, but the request could still apply until "
                         f"{clock(answer['apply_before_unix_ms'])} UTC.")
            else:
                heard = (f"provider: no such refund, and the deadline {clock(answer['apply_before_unix_ms'])} UTC "
                         f"has passed, so it can never apply.")
            self.beat(5, "Independent evidence arrives" if reconciled["status"] == "settled"
                      else "Independent evidence (not yet enough)",
                      f"A separate observer asks the provider directly at {clock(seen['asked_at_unix_ms'])} UTC.\n"
                      + heard + f"\nDocket now says: {reconciled['status'].upper()}.")
            if reconciled["status"] == "settled" or step >= 3:
                break
            wait = max(0.0, (plan["apply_before_unix_ms"] - now_ms()) / 1000) + 1.2
            self.say(f"          Waiting {wait:.1f}s for the deadline to pass, then asking again.")
            time.sleep(wait)

        final = self.inspect(body["issuance"])
        self.write(home / "docket-final.json", final)
        record = final["record"]
        if record["status"] == "settled":
            settlement = record["settlement"]
            self.beat(6, "Final disposition",
                      f"Docket settles the attempt as {settlement['outcome'].upper()}.\n"
                      f"It cites the observer's document {settlement['receipt'][:23]}... as its receipt,\n"
                      f"and keeps the earlier INDETERMINATE evidence {record['indeterminate']['evidence'][:23]}...")
        else:
            self.beat(6, "Final disposition", f"Docket still says {record['status'].upper()}.")
        network = [json.loads(line) for line in (home / "network.log").read_text().splitlines()]
        events = "; ".join(("the request reached the provider, which answered " + e["provider_status"].split(" ", 1)[1]
                            + ";\n           the reply was dropped") if e["forwarded"]
                           else "the request was dropped before it reached the provider" for e in network)
        self.say(f"          (Behind the scenes, from the network log:\n           {events}.)")

    def summary(self) -> None:
        rows = []
        for name in ("A-lost-reply", "B-lost-request"):
            claim = json.loads((self.out / name / "agent-claim.json").read_text())
            first = json.loads((self.out / name / "docket-after-accept.json").read_text())["record"]
            final = json.loads((self.out / name / "docket-final.json").read_text())["record"]
            outcome = final["settlement"]["outcome"] if final["settlement"] else final["status"]
            rows.append((name, claim["basis"], first["status"], outcome))
        self.say()
        self.say("=== Summary ===")
        self.say(f"{'run':<16}{'agent said':<22}{'Docket at first':<18}{'Docket at the end'}")
        for name, basis, first, outcome in rows:
            self.say(f"{name:<16}{'done (exit ' + basis.split()[-1] + ')':<22}{first:<18}{outcome}")
        self.say('The agent said "done" both times. The final answers differ, and each one follows')
        self.say("what the provider's own records show, not what the agent said.")
        self.say(f"Check it yourself: python3 {short(HERE / 'check.py')} {short(self.out)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docket-bin", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args()
    demo = Demo(args.docket_bin.resolve(), args.out.resolve())
    try:
        demo.setup()
        demo.scenario("A-lost-reply", "Run A: the reply goes missing", "lose-reply", "1042", 4000)
        demo.scenario("B-lost-request", "Run B: the request goes missing", "lose-request", "1043", 2500)
        demo.summary()
    finally:
        demo.stop()
        key = args.out.resolve() / "authority" / "issuer-private.der"
        if key.exists():
            key.unlink()


if __name__ == "__main__":
    main()
