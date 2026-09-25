//! Docket mirror of AG's governed-loop issuance conformance corpus.
//!
//! `conformance/ag-governed-loop-issuance/v2-vectors.json` is a byte-for-byte
//! mirror of `unpingable/constellation-ag`
//! `conformance/governed-loop-issuance/v2-vectors.json`; AG's own test pins
//! the same SHA-256. A drift in either repository fails that repository's
//! suite. Docket's production verifier and dispatch predicate must agree
//! with every vector.

use gwr_local::governed_loop::verify_signed_issuance;
use gwr_runtime::governed_loop::{issuance_identity, require_issuance_current};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const CORPUS: &[u8] =
    include_bytes!("../../../conformance/ag-governed-loop-issuance/v2-vectors.json");
/// Pinned identically in AG's owning test.
const CORPUS_SHA256: &str = "b715ddcf1d04ca751d8bfb9d81dee1a4dc68db131a7d3c05df3f7f6133eaf513";

#[test]
fn docket_verifier_agrees_with_every_ag_issuance_vector() {
    let digest = Sha256::digest(CORPUS);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, CORPUS_SHA256, "mirror drifted from AG's corpus");
    let corpus: Value = serde_json::from_slice(CORPUS).unwrap();
    let trust = serde_json::to_vec(&corpus["trust"]).unwrap();
    let mut names = Vec::new();
    for vector in corpus["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        names.push(name);
        let envelope = serde_json::to_vec(&vector["envelope"]).unwrap();
        let verified = verify_signed_issuance(&envelope, &trust);
        match vector["verify"].as_str().unwrap() {
            "ok" => {
                let (_, issuance) = verified.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(issuance.issuance, vector["issuance"].as_str().unwrap());
                assert_eq!(issuance_identity(&issuance).unwrap(), issuance.issuance);
                assert_eq!(
                    serde_json::to_string(&serde_json::to_value(&issuance).unwrap()).unwrap(),
                    vector["body_jcs"].as_str().unwrap(),
                    "{name}"
                );
                for check in vector["dispatch"].as_array().unwrap() {
                    let now = check["now_unix_ms"].as_u64().unwrap();
                    let expected = check["expect"].as_str().unwrap();
                    match require_issuance_current(&issuance, now) {
                        Ok(()) => assert_eq!(expected, "current", "{name} at {now}"),
                        Err(error) => assert_eq!(error, expected, "{name} at {now}"),
                    }
                }
            }
            refusal => assert_eq!(verified.unwrap_err(), refusal, "{name}"),
        }
    }
    assert_eq!(names.len(), 6);
    assert!(names.contains(&"v1-alpha6-retained"));
}
