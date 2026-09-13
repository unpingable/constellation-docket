-- Canonical AG governed-loop execution custody.
--
-- These tables are deliberately separate from campaign-stage standing and
-- general Git-effect standing.  One authenticated AG issuance consumes one
-- Docket-owned execution standing and creates one canonical physical attempt.
-- Every field is an explicit scalar column; no serialized JSON is treated as
-- authoritative state.

CREATE TABLE IF NOT EXISTS governed_execution_standing_use (
    execution_standing TEXT PRIMARY KEY,
    issuance TEXT NOT NULL UNIQUE,
    standing_resolution TEXT NOT NULL,
    standing_currentness TEXT NOT NULL,
    consumed_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS governed_loop_attempt (
    issuance TEXT PRIMARY KEY,
    signed_body_b64 TEXT NOT NULL,
    issuer_principal TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    signer_public_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    campaign TEXT NOT NULL,
    occurrence TEXT NOT NULL,
    program TEXT NOT NULL,
    proposal TEXT NOT NULL,
    work_schema TEXT NOT NULL,
    work TEXT NOT NULL,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    observation TEXT NOT NULL,
    ag_standing_resolution TEXT NOT NULL,
    mandate TEXT NOT NULL,
    ag_spend TEXT NOT NULL UNIQUE,
    execution_standing TEXT NOT NULL UNIQUE,
    standing_currentness TEXT NOT NULL,
    attempt TEXT NOT NULL UNIQUE,
    executor_marker TEXT NOT NULL UNIQUE,
    executor_binding TEXT NOT NULL,
    executor_program_digest TEXT NOT NULL,
    executor_plan TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('accepted','settled','indeterminate')),
    settlement TEXT,
    receipt TEXT,
    outcome TEXT CHECK (outcome IS NULL OR outcome IN ('success','failure')),
    settled_at INTEGER,
    reconciliation TEXT,
    indeterminate_evidence TEXT,
    CHECK (
      (status = 'accepted' AND settlement IS NULL AND receipt IS NULL AND outcome IS NULL
                           AND settled_at IS NULL AND reconciliation IS NULL
                           AND indeterminate_evidence IS NULL)
      OR
      (status = 'settled' AND settlement IS NOT NULL AND receipt IS NOT NULL AND outcome IS NOT NULL
                          AND settled_at IS NOT NULL)
      OR
      (status = 'indeterminate' AND reconciliation IS NOT NULL
                                AND indeterminate_evidence IS NOT NULL)
    )
) STRICT;
