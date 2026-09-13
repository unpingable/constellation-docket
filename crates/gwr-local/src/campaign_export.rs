//! The canonical JSON projection of the repair-authority bundle (P1).
//!
//! The Docket-owned artifact is deterministic: fixed key order, two-space
//! indentation, LF line endings, one trailing newline. String encoding is
//! JSON-standard (serde_json is used for string escaping only; the document
//! is assembled by hand so key order can never drift). The typed Docket
//! content address travels inside the artifact as `docket_repair_authority`;
//! the file's own identity is SHA-256 over the exact file bytes and travels
//! alongside in a `<file>.sha256` companion — the artifact never embeds its
//! own file digest, and no consumer re-canonicalizes.

use gwr_core::campaign::adjudication::AdjudicationVerdict;
use gwr_core::campaign::authority::RepairAuthorityV1;
use gwr_core::campaign::proposal::RepoPin;
use gwr_core::campaign::{RepairScopeClass, StageClass, StageEffectClass, WorkerRole};
use gwr_core::digest::Sha256Digest;
use gwr_core::work_request::{ClockReading, CommitHash, RepositoryLocator};
use sha2::{Digest, Sha256};

/// The one schema identity. Unknown or missing schemas refuse at parse.
pub const REPAIR_AUTHORITY_SCHEMA: &str = "gwr:campaign-repair-authority:v1";

/// SHA-256 over exact bytes, lowercase hex — the file-identity rule.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn js(s: &str) -> String {
    serde_json::to_string(s).expect("string escaping cannot fail")
}

fn jd(d: &Sha256Digest) -> String {
    js(&format!("sha256:{}", d.to_hex()))
}

fn jss(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| js(s)).collect();
    format!("[{}]", inner.join(", "))
}

/// Render the canonical JSON document for a bundle.
pub fn render(b: &RepairAuthorityV1) -> String {
    let consumption = match &b.consumption {
        Some(c) => jd(c),
        None => "null".to_string(),
    };
    let repos: Vec<String> = b
        .repositories
        .iter()
        .map(|p| {
            format!(
                "{{\"repository\": {}, \"commit\": {}, \"tree\": {}}}",
                js(p.repository.as_str()),
                js(p.commit.as_str()),
                js(&p.tree)
            )
        })
        .collect();
    let mut out = String::new();
    let w = |out: &mut String, key: &str, value: String| {
        out.push_str(&format!("  {}: {},\n", js(key), value));
    };
    out.push_str("{\n");
    w(&mut out, "schema", js(REPAIR_AUTHORITY_SCHEMA));
    w(&mut out, "docket_repair_authority", jd(&b.digest));
    w(&mut out, "campaign", js(&b.campaign));
    w(&mut out, "repair_stage", js(&b.repair_stage));
    w(&mut out, "role", js(b.role.tag()));
    w(&mut out, "stage_class", js(b.stage_class.tag()));
    w(&mut out, "effect_class", js(b.effect_class.tag()));
    w(&mut out, "standing", jd(&b.standing));
    w(&mut out, "proposal_digest", jd(&b.proposal_digest));
    w(&mut out, "consumption", consumption);
    w(&mut out, "original_stage", js(&b.original_stage));
    w(
        &mut out,
        "original_proposal_digest",
        jd(&b.original_proposal_digest),
    );
    w(&mut out, "original_standing", jd(&b.original_standing));
    w(
        &mut out,
        "original_consumption",
        jd(&b.original_consumption),
    );
    w(
        &mut out,
        "rejected_review_receipt",
        jd(&b.rejected_review_receipt),
    );
    w(&mut out, "adjudication", jd(&b.adjudication));
    w(
        &mut out,
        "adjudication_verdict",
        js(b.adjudication_verdict.tag()),
    );
    w(&mut out, "finding_ids", jss(&b.finding_ids));
    w(&mut out, "scope_class", js(b.scope_class.tag()));
    w(&mut out, "repositories", format!("[{}]", repos.join(", ")));
    w(&mut out, "allowed_paths", jss(&b.allowed_paths));
    w(&mut out, "expires_at_ms", b.expires_at.0.to_string());
    w(&mut out, "nonce", js(&b.nonce));
    w(&mut out, "nonclaims", jss(&b.nonclaims));
    out.push_str(&format!("  {}: {}\n", js("verifier"), js(&b.verifier)));
    out.push_str("}\n");
    out
}

fn pdigest(v: &serde_json::Value, key: &str) -> Result<Sha256Digest, String> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing or non-string field {key}"))?;
    let hex = s
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("field {key} lacks the sha256: prefix"))?;
    crate::store::codec::parse_digest(hex).map_err(|_| format!("bad digest in field {key}"))
}

fn pstring(v: &serde_json::Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing or non-string field {key}"))
}

fn pstrings(v: &serde_json::Value, key: &str) -> Result<Vec<String>, String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| format!("missing or non-array field {key}"))?
        .iter()
        .map(|x| {
            x.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("non-string element in {key}"))
        })
        .collect()
}

/// The exact key set, in canonical order. Anything else — an omission, an
/// addition, or a reordered-but-equal document with different bytes — is not
/// this artifact.
const KEYS: &[&str] = &[
    "schema",
    "docket_repair_authority",
    "campaign",
    "repair_stage",
    "role",
    "stage_class",
    "effect_class",
    "standing",
    "proposal_digest",
    "consumption",
    "original_stage",
    "original_proposal_digest",
    "original_standing",
    "original_consumption",
    "rejected_review_receipt",
    "adjudication",
    "adjudication_verdict",
    "finding_ids",
    "scope_class",
    "repositories",
    "allowed_paths",
    "expires_at_ms",
    "nonce",
    "nonclaims",
    "verifier",
];

/// Parse a canonical artifact. Refuses: malformed JSON, unknown schema,
/// missing or added fields, wrong types, unknown enum tags, malformed
/// digests, and an embedded typed digest that does not recompute from the
/// fields.
pub fn parse(raw: &str) -> Result<RepairAuthorityV1, String> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("malformed JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "artifact is not a JSON object".to_string())?;
    for key in obj.keys() {
        if !KEYS.contains(&key.as_str()) {
            return Err(format!("unknown field {key}"));
        }
    }
    for key in KEYS {
        if !obj.contains_key(*key) {
            return Err(format!("missing field {key}"));
        }
    }
    if pstring(&v, "schema")? != REPAIR_AUTHORITY_SCHEMA {
        return Err(format!(
            "unknown schema; expected {REPAIR_AUTHORITY_SCHEMA}"
        ));
    }
    let embedded = pdigest(&v, "docket_repair_authority")?;
    let consumption = match v.get("consumption") {
        Some(serde_json::Value::Null) => None,
        _ => Some(pdigest(&v, "consumption")?),
    };
    let repositories = v
        .get("repositories")
        .and_then(|x| x.as_array())
        .ok_or("missing or non-array field repositories")?
        .iter()
        .map(|p| {
            Ok(RepoPin {
                repository: RepositoryLocator::new(&pstring(p, "repository")?),
                commit: CommitHash::new(&pstring(p, "commit")?),
                tree: pstring(p, "tree")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let expires_at_ms = v
        .get("expires_at_ms")
        .and_then(|x| x.as_u64())
        .ok_or("missing or non-integer field expires_at_ms")?;
    let bundle = RepairAuthorityV1::issue(
        pstring(&v, "campaign")?,
        pstring(&v, "repair_stage")?,
        WorkerRole::from_tag(&pstring(&v, "role")?).ok_or("unknown role tag")?,
        StageClass::from_tag(&pstring(&v, "stage_class")?).ok_or("unknown stage class tag")?,
        StageEffectClass::from_tag(&pstring(&v, "effect_class")?)
            .ok_or("unknown effect class tag")?,
        pdigest(&v, "standing")?,
        pdigest(&v, "proposal_digest")?,
        consumption,
        pstring(&v, "original_stage")?,
        pdigest(&v, "original_proposal_digest")?,
        pdigest(&v, "original_standing")?,
        pdigest(&v, "original_consumption")?,
        pdigest(&v, "rejected_review_receipt")?,
        pdigest(&v, "adjudication")?,
        AdjudicationVerdict::from_tag(&pstring(&v, "adjudication_verdict")?)
            .ok_or("unknown adjudication verdict tag")?,
        pstrings(&v, "finding_ids")?,
        RepairScopeClass::from_tag(&pstring(&v, "scope_class")?)
            .ok_or("unknown scope class tag")?,
        repositories,
        pstrings(&v, "allowed_paths")?,
        ClockReading(expires_at_ms),
        pstring(&v, "nonce")?,
        pstrings(&v, "nonclaims")?,
        pstring(&v, "verifier")?,
    )
    .map_err(|e| format!("artifact fails construction law: {e:?}"))?;
    if bundle.digest != embedded {
        return Err("docket_repair_authority does not recompute from the artifact fields".into());
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use gwr_runtime::services::campaign as svc;

    /// Build a real adjudicated repair chain in a store and export the
    /// bundle; the render/parse round-trip and the service verification
    /// both hold.
    #[test]
    fn render_parse_round_trip_and_service_verification() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let bundle = crate::campaign_export::tests_support::adjudicated_repair_bundle(&mut store);
        let raw = render(&bundle);
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed, bundle);
        assert_eq!(sha256_hex(raw.as_bytes()), sha256_hex(raw.as_bytes()));
        svc::verify_repair_authority(&mut store, &parsed, ClockReading(5_500), &bundle.verifier)
            .unwrap();
        // Byte-level tampering refuses at parse or at digest recompute.
        let tampered = raw.replacen("docs/x.md", "docs/y.md", 1);
        assert!(parse(&tampered).is_err());
        // Field omission and addition refuse.
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v.as_object_mut().unwrap().remove("nonce");
        assert!(parse(&serde_json::to_string(&v).unwrap()).is_err());
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::Null);
        assert!(parse(&serde_json::to_string(&v).unwrap()).is_err());
        // Unknown schema refuses.
        let raw2 = raw.replacen(REPAIR_AUTHORITY_SCHEMA, "gwr:other:v9", 1);
        assert!(parse(&raw2).is_err());
    }
}

/// Shared fixture used by the export tests and the CLI-facing integration
/// tests: a consumed, adjudicated original stage and an admitted repair
/// standing, exported.
#[cfg(test)]
pub(crate) mod tests_support {
    use gwr_core::campaign::adjudication::AdjudicationVerdict;
    use gwr_core::campaign::authority::RepairAuthorityV1;
    use gwr_core::campaign::proposal::{CampaignStageProposal, RepairBasis, RepoPin, StageBasis};
    use gwr_core::campaign::standing::ExecutionContext;
    use gwr_core::campaign::{RepairScopeClass, ReviewRequirement, StageClass, WorkerRole};
    use gwr_core::digest::Sha256Digest;
    use gwr_core::work_request::{ClockReading, CommitHash, RepositoryLocator};
    use gwr_runtime::services::campaign as svc;

    use crate::store::SqliteStore;

    pub const COMMIT_A: &str = "72cb3b323fa286cd212378eadae4a42fe4dc093e";
    pub const TREE_A: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    pub const REVIEW_RECEIPT: Sha256Digest = Sha256Digest::from_bytes([9; 32]);
    pub const VERIFIER: &str = "gwr-local test";

    pub fn adjudicated_repair_bundle(store: &mut SqliteStore) -> RepairAuthorityV1 {
        let pin = RepoPin {
            repository: RepositoryLocator::new("/repo"),
            commit: CommitHash::new(COMMIT_A),
            tree: TREE_A.into(),
        };
        let original = CampaignStageProposal::propose(
            "upstream-0".into(),
            "camp-1".into(),
            "stage-a".into(),
            StageClass::OperatorStage,
            WorkerRole::Operator,
            gwr_core::campaign::StageEffectClass::WorkspaceMutation,
            StageBasis::RootAuthorization {
                identity: "root-auth-1".into(),
            },
            vec![pin.clone()],
            vec!["src/lib.rs".into(), "docs/x.md".into()],
            "evidence-contract-1".into(),
            "handoff-schema-1".into(),
            ClockReading(10_000),
            "nonce-1".into(),
            String::new(),
            ReviewRequirement::Required,
            vec!["does-not-establish-correctness".into()],
            None,
            ClockReading(1_000),
        )
        .unwrap();
        svc::propose_stage(store, &original).unwrap();
        let standing = svc::admit(store, &original.digest, ClockReading(2_000)).unwrap();
        let ctx = ExecutionContext {
            campaign: "camp-1".into(),
            stage: "stage-a".into(),
            role: WorkerRole::Operator,
            proposal_digest: original.digest,
        };
        svc::consume(store, &standing.digest(), &ctx, ClockReading(3_000)).unwrap();
        svc::record_receipt(store, &standing.digest(), &REVIEW_RECEIPT).unwrap();
        let adjudication = svc::adjudicate(
            store,
            "camp-1",
            "stage-a",
            &REVIEW_RECEIPT,
            AdjudicationVerdict::ExactRepair,
            "adjudicator-1",
            vec!["finding-1".into()],
            vec![],
            ClockReading(4_000),
        )
        .unwrap();
        let repair = CampaignStageProposal::propose(
            "upstream-repair".into(),
            "camp-1".into(),
            "stage-a-repair".into(),
            StageClass::RecordsRepairStage,
            WorkerRole::Repair,
            gwr_core::campaign::StageEffectClass::RecordsOnly,
            StageBasis::PredecessorStage {
                stage: "stage-a".into(),
                adjudication_digest: adjudication.digest,
            },
            vec![pin],
            vec!["docs/x.md".into()],
            "evidence-contract-1".into(),
            "handoff-schema-1".into(),
            ClockReading(10_000),
            "nonce-repair".into(),
            String::new(),
            ReviewRequirement::Required,
            vec!["does-not-widen-scope".into()],
            Some(RepairBasis {
                original_stage: "stage-a".into(),
                rejected_review_receipt: REVIEW_RECEIPT,
                finding_ids: vec!["finding-1".into()],
                scope_class: RepairScopeClass::RecordsOnly,
                nonclaims: vec!["does-not-widen-scope".into()],
                review_requirement: ReviewRequirement::Required,
            }),
            ClockReading(4_500),
        )
        .unwrap();
        svc::propose_stage(store, &repair).unwrap();
        let repair_standing = svc::admit(store, &repair.digest, ClockReading(5_000)).unwrap();
        svc::export_repair_authority(
            store,
            &repair_standing.digest(),
            ClockReading(5_500),
            VERIFIER,
        )
        .unwrap()
    }
}
