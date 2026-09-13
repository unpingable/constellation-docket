-- Campaign-stage standing (S-2). A distinct ledger from effect standing:
-- content-addressed proposals and standings, one durable consumption per
-- standing (burn-before-effect), adjudication receipts, and preserved
-- residual obligations. All list and record encodings are explicit and
-- length-prefixed (see store/codec.rs); there is no JSON here.

CREATE TABLE IF NOT EXISTS campaign_stage_proposal (
    digest TEXT PRIMARY KEY,
    upstream_digest TEXT NOT NULL,
    campaign TEXT NOT NULL,
    stage TEXT NOT NULL,
    stage_class TEXT NOT NULL,
    role TEXT NOT NULL,
    effect_class TEXT NOT NULL,
    basis_kind TEXT NOT NULL,
    basis_identity TEXT NOT NULL,
    basis_stage TEXT NOT NULL,
    basis_adjudication TEXT,
    repositories TEXT NOT NULL,
    allowed_paths TEXT NOT NULL,
    evidence_contract TEXT NOT NULL,
    handoff_schema TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    isolated_worktree TEXT NOT NULL,
    review_requirement TEXT NOT NULL,
    nonclaims TEXT NOT NULL,
    repair_basis TEXT,
    proposed_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS campaign_stage_standing (
    digest TEXT PRIMARY KEY,
    proposal_digest TEXT NOT NULL,
    upstream_digest TEXT NOT NULL,
    campaign TEXT NOT NULL,
    stage TEXT NOT NULL,
    stage_class TEXT NOT NULL,
    role TEXT NOT NULL,
    effect_class TEXT NOT NULL,
    repositories TEXT NOT NULL,
    allowed_paths TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    issued_at INTEGER NOT NULL
) STRICT;

-- The durable burn. effect_completed and receipt are filled in as the
-- outcome becomes known; receipt is the consuming receipt's digest, verbatim.
CREATE TABLE IF NOT EXISTS campaign_stage_consumption (
    standing TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    campaign TEXT NOT NULL,
    stage TEXT NOT NULL,
    role TEXT NOT NULL,
    consumed_at INTEGER NOT NULL,
    effect_completed INTEGER NOT NULL,
    receipt TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS campaign_stage_adjudication (
    digest TEXT PRIMARY KEY,
    campaign TEXT NOT NULL,
    stage TEXT NOT NULL,
    review_receipt TEXT NOT NULL,
    verdict TEXT NOT NULL,
    adjudicator TEXT NOT NULL,
    findings TEXT NOT NULL,
    residuals TEXT NOT NULL,
    adjudicated_at INTEGER NOT NULL
) STRICT;

-- Residual obligations, one row each, preserved. No discharge anywhere.
CREATE TABLE IF NOT EXISTS campaign_residual_obligation (
    adjudication TEXT NOT NULL,
    campaign TEXT NOT NULL,
    stage TEXT NOT NULL,
    kind TEXT NOT NULL,
    statement TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;
