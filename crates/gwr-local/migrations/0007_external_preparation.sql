-- Local custody of externally submitted preparation testimony. These scalar
-- fields are not provider testimony, trusted observation, or effect authority.
-- Existing preparation records acquire no inferred external provenance.
CREATE TABLE IF NOT EXISTS external_preparation (
    repository_id TEXT NOT NULL,
    submission_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    work_request TEXT NOT NULL REFERENCES work_request(id),
    basis TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    content_len INTEGER NOT NULL CHECK (content_len >= 0),
    deadline INTEGER NOT NULL CHECK (deadline >= 0),
    origin_kind TEXT NOT NULL CHECK (origin_kind IN ('external-session', 'human')),
    origin_identity TEXT NOT NULL,
    origin_tool TEXT,
    repository_locator TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    preparation_run TEXT NOT NULL UNIQUE REFERENCES preparation_run(id),
    candidate TEXT NOT NULL UNIQUE REFERENCES candidate_artifact(id),
    PRIMARY KEY (repository_id, submission_id)
) STRICT;

CREATE TRIGGER IF NOT EXISTS external_preparation_no_update
BEFORE UPDATE ON external_preparation
BEGIN SELECT RAISE(ABORT, 'external preparation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS external_preparation_no_delete
BEFORE DELETE ON external_preparation
BEGIN SELECT RAISE(ABORT, 'external preparation is immutable'); END;
