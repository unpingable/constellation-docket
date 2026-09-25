# SPDX-License-Identifier: Apache-2.0
"""Stand-in for the authorizing service (constellation-ag) that signs the work order.

The real AG mints this signed authorization only inside its own run loop, which
needs a full deployment profile. This demo does not run AG. Instead, this module
signs with the same rule, using Python's standard library and `openssl pkeyutl`:
canonical JSON body, domain-separated identity digest, Ed25519 over a fixed
prefix plus the body. `self_check` proves the rule by reproducing AG's published
conformance vector (`conformance/ag-governed-loop-issuance/v2-vectors.json`,
owned by constellation-ag and mirrored in this repository) byte for byte.
The demo's signing key is fresh and throwaway.
"""
import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "conformance/ag-governed-loop-issuance/v2-vectors.json"
ED25519_PKCS8_V1_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def compact(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_domain(domain: str, payload: bytes) -> str:
    digest = hashlib.sha256(b"ag-ng\0digest\0v1\0")
    digest.update(len(domain).to_bytes(16, "big") + domain.encode())
    digest.update(len(payload).to_bytes(16, "big") + payload)
    return "sha256:" + digest.hexdigest()


def identity(body: dict) -> str:
    basis = {k: v for k, v in body.items() if k not in ("schema", "issuance")}
    return hash_domain(body["schema"], compact(basis))


def _openssl(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def generate_key(path: pathlib.Path) -> None:
    _openssl("genpkey", "-algorithm", "Ed25519", "-outform", "DER", "-out", str(path))
    path.chmod(0o600)


def public_key(key_der: pathlib.Path) -> bytes:
    return _openssl("pkey", "-inform", "DER", "-in", str(key_der), "-pubout", "-outform", "DER")[-32:]


def sign(key_der: pathlib.Path, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        (pathlib.Path(tmp) / "m").write_bytes(message)
        return _openssl("pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", str(key_der),
                        "-in", str(pathlib.Path(tmp) / "m"))


def envelope(body: dict, key_der: pathlib.Path, principal: str, key_id: str) -> dict:
    prefix = unb64(json.loads(VECTORS.read_text())["signature_prefix_b64"])
    raw = compact(body)
    return {"schema": "ag.governed-loop.signed-issuance/v1", "body_b64": b64(raw),
            "authentication": {"issuer_principal": principal, "signer_key_id": key_id,
                               "signer_public_key": b64(public_key(key_der)),
                               "signature": b64(sign(key_der, prefix + raw))}}


def self_check(scratch: pathlib.Path) -> str:
    """Reproduce AG's v2-current vector byte for byte; return the vector file's sha256."""
    corpus_bytes = VECTORS.read_bytes()
    corpus = json.loads(corpus_bytes)
    vector = next(v for v in corpus["vectors"] if v["name"] == "v2-current")
    # The corpus key is PKCS#8 v2, which OpenSSL 3.0 cannot load; re-wrap its seed as PKCS#8 v1.
    v2 = unb64(corpus["test_signing_key_pkcs8_v2_b64"])
    key = scratch / "conformance-key.der"
    key.write_bytes(ED25519_PKCS8_V1_PREFIX + v2[16:48])
    try:
        body = json.loads(vector["body_jcs"])
        if compact(body).decode() != vector["body_jcs"] or identity(body) != vector["issuance"]:
            raise SystemExit("stand-in signer: body or identity rule differs from AG's vector")
        produced = envelope(body, key, "conformance.ag-issuer", "conformance.ag-issuer.v2-vectors")
        if produced != vector["envelope"]:
            raise SystemExit("stand-in signer does not reproduce AG's vector envelope")
    finally:
        key.unlink()
    return hashlib.sha256(corpus_bytes).hexdigest()
