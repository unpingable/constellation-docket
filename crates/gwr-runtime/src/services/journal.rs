//! Verified journal inspection: a read-only view of the broker journal the
//! store records for a dispatch.
//!
//! The journal is displayed as evidence only after its bytes hash to the
//! digest the runtime persisted when the outcome was recorded (commitment,
//! dispatch refusal, or indeterminacy). An unverified journal is never
//! rendered as evidence: on digest mismatch, corruption, or a missing
//! recorded digest, the view carries the typed status and the digests — not
//! the content.
//!
//! The journal's phase vocabulary is closed. A digest-verified journal
//! containing a line outside it is classified `Corrupt` and its content is
//! withheld; this is the surface's redaction rule, and it is explicit rather
//! than silent — the status names the offending line number. (Broker journals
//! contain phases, commit hashes, and refusal grounds only; no provider
//! output, tokens, or authority material can appear in a well-formed one.)
//!
//! Verification establishes what the recorded journal says and that its bytes
//! match the persisted digest. It does not independently prove that every
//! journal statement is true.

use gwr_core::digest::Sha256Digest;
use gwr_core::ids::{AttemptId, DispatchId};
use gwr_core::outcome::{Commitment, DispatchRefusalRecord, IndeterminateRecord};
use gwr_core::refusal::DispatchRefusalGround;
use gwr_core::work_request::CommitHash;

/// The versioned JSON format identifier for journal views.
pub const JOURNAL_FORMAT: &str = "gwr:journal-view:v1";

/// What the store's own records lead the reader to expect of the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalExpectation {
    /// No dispatch exists for the attempt; there is nothing to inspect.
    NoDispatch,
    /// A dispatch exists but no outcome record carries a journal digest, so
    /// nothing on disk can be verified against the runtime's record.
    NoRecordedDigest,
    /// An outcome record persisted this digest of the journal.
    Digest(Sha256Digest),
}

/// Derive the expectation from the persisted outcome records. Priority is the
/// record that terminated the dispatch: commitment, then definitive refusal,
/// then the digest recorded at indeterminacy (which recovery later verified
/// against, so it remains authoritative for recovery-settled attempts).
pub fn expectation(
    dispatched: bool,
    commitment: Option<&Commitment>,
    refusal: Option<&DispatchRefusalRecord>,
    indeterminate: Option<&IndeterminateRecord>,
) -> JournalExpectation {
    if let Some(c) = commitment {
        return JournalExpectation::Digest(c.journal_digest);
    }
    if let Some(r) = refusal {
        return JournalExpectation::Digest(r.journal_digest);
    }
    if let Some(i) = indeterminate {
        return match i.last_journal_digest {
            Some(d) => JournalExpectation::Digest(d),
            None => JournalExpectation::NoRecordedDigest,
        };
    }
    if dispatched {
        JournalExpectation::NoRecordedDigest
    } else {
        JournalExpectation::NoDispatch
    }
}

/// One journal phase, exactly as journalled, in exact order. The vocabulary is
/// closed; anything outside it makes the journal `Corrupt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEvent {
    Received,
    Verified,
    PatchApplied,
    PathsAuthorized,
    TreeWritten,
    CommitCreated(CommitHash),
    RefUpdating,
    RefUpdated {
        previous: CommitHash,
        result: CommitHash,
    },
    Acknowledged,
    Refused(DispatchRefusalGround),
}

impl JournalEvent {
    fn parse(line: &str) -> Option<Self> {
        Some(match line {
            "received" => Self::Received,
            "verified" => Self::Verified,
            "patch_applied" => Self::PatchApplied,
            "paths_authorized" => Self::PathsAuthorized,
            "tree_written" => Self::TreeWritten,
            "ref_updating" => Self::RefUpdating,
            "acknowledged" => Self::Acknowledged,
            _ => {
                if let Some(hash) = line.strip_prefix("commit_created ") {
                    Self::CommitCreated(CommitHash::new(hash))
                } else if let Some(rest) = line.strip_prefix("ref_updated ") {
                    let (previous, result) = rest.split_once(' ')?;
                    Self::RefUpdated {
                        previous: CommitHash::new(previous),
                        result: CommitHash::new(result),
                    }
                } else {
                    let ground = line.strip_prefix("refused ")?;
                    Self::Refused(DispatchRefusalGround::from_tag(ground)?)
                }
            }
        })
    }

    /// Whether this phase terminates a journal: the broker exits cleanly only
    /// after acknowledging or definitively refusing.
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Acknowledged | Self::Refused(_))
    }

    pub fn phase_tag(&self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Verified => "verified",
            Self::PatchApplied => "patch_applied",
            Self::PathsAuthorized => "paths_authorized",
            Self::TreeWritten => "tree_written",
            Self::CommitCreated(_) => "commit_created",
            Self::RefUpdating => "ref_updating",
            Self::RefUpdated { .. } => "ref_updated",
            Self::Acknowledged => "acknowledged",
            Self::Refused(_) => "refused",
        }
    }
}

/// The verification status of the journal. Only the two `Verified*` statuses
/// carry events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalStatus {
    /// Nothing can be verified: no dispatch, or no recorded digest.
    Unavailable { reason: &'static str },
    /// The store records a digest but no journal bytes exist to inspect.
    Missing,
    /// The journal bytes do not hash to the persisted digest. Content is
    /// withheld: an unverified journal is not evidence.
    DigestMismatch {
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    /// The bytes match the digest but are not a well-formed journal (non-UTF-8
    /// content or a line outside the closed vocabulary). Content is withheld.
    Corrupt { line_number: usize, reason: String },
    /// Digest verified; the journal does not reach a terminal phase — exactly
    /// the shape a broker crash leaves behind.
    VerifiedPartial,
    /// Digest verified; the journal ends `acknowledged` or `refused`.
    VerifiedComplete,
}

impl JournalStatus {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "unavailable",
            Self::Missing => "missing",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::Corrupt { .. } => "corrupt",
            Self::VerifiedPartial => "verified_partial",
            Self::VerifiedComplete => "verified_complete",
        }
    }

    pub fn verified(&self) -> bool {
        matches!(self, Self::VerifiedPartial | Self::VerifiedComplete)
    }
}

/// The canonical journal view. Both renderings are pure functions of this one
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalView {
    pub attempt: AttemptId,
    pub dispatch: Option<DispatchId>,
    pub expected_digest: Option<Sha256Digest>,
    /// Digest of the bytes actually found, when any were found.
    pub actual_digest: Option<Sha256Digest>,
    pub status: JournalStatus,
    /// Present exactly when the status is verified; exact journal order.
    pub events: Vec<JournalEvent>,
}

/// Build the view from the store-derived expectation and the raw bytes found
/// (or not) at the journal location the store's dispatch binding names. Pure:
/// all I/O — record reads and byte loading — happens in the caller.
pub fn inspect(
    attempt: AttemptId,
    dispatch: Option<DispatchId>,
    expectation: JournalExpectation,
    bytes: Option<&[u8]>,
) -> JournalView {
    let actual_digest = bytes.map(Sha256Digest::of_bytes);
    let (status, events) = match &expectation {
        JournalExpectation::NoDispatch => (
            JournalStatus::Unavailable {
                reason: "no dispatch exists for this attempt",
            },
            Vec::new(),
        ),
        JournalExpectation::NoRecordedDigest => (
            JournalStatus::Unavailable {
                reason: "no journal digest was recorded for this dispatch; nothing on disk \
                         can be verified against the runtime's record",
            },
            Vec::new(),
        ),
        JournalExpectation::Digest(expected) => match (bytes, actual_digest) {
            (None, _) => (JournalStatus::Missing, Vec::new()),
            (Some(_), Some(actual)) if actual != *expected => (
                JournalStatus::DigestMismatch {
                    expected: *expected,
                    actual,
                },
                Vec::new(),
            ),
            (Some(raw), _) => match std::str::from_utf8(raw) {
                Err(_) => (
                    JournalStatus::Corrupt {
                        line_number: 0,
                        reason: "journal bytes are not UTF-8".into(),
                    },
                    Vec::new(),
                ),
                Ok(text) => {
                    let mut events = Vec::new();
                    let mut corrupt = None;
                    for (i, line) in text.lines().enumerate() {
                        match JournalEvent::parse(line) {
                            Some(ev) => events.push(ev),
                            None => {
                                corrupt = Some(JournalStatus::Corrupt {
                                    line_number: i + 1,
                                    reason: "line outside the journal's closed vocabulary".into(),
                                });
                                break;
                            }
                        }
                    }
                    match corrupt {
                        Some(status) => (status, Vec::new()),
                        None => {
                            let complete = events
                                .last()
                                .map(JournalEvent::is_terminal)
                                .unwrap_or(false);
                            (
                                if complete {
                                    JournalStatus::VerifiedComplete
                                } else {
                                    JournalStatus::VerifiedPartial
                                },
                                events,
                            )
                        }
                    }
                }
            },
        },
    };
    let expected_digest = match expectation {
        JournalExpectation::Digest(d) => Some(d),
        _ => None,
    };
    JournalView {
        attempt,
        dispatch,
        expected_digest,
        actual_digest,
        status,
        events,
    }
}

fn hx(bytes: &[u8; 16]) -> String {
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn event_detail(ev: &JournalEvent) -> Option<String> {
    match ev {
        JournalEvent::CommitCreated(c) => Some(c.as_str().to_string()),
        JournalEvent::RefUpdated { previous, result } => {
            Some(format!("{} {}", previous.as_str(), result.as_str()))
        }
        JournalEvent::Refused(g) => Some(g.tag().to_string()),
        _ => None,
    }
}

/// Human rendering. Same source value as the JSON rendering.
pub fn render_journal_text(v: &JournalView) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "attempt {}", hx(v.attempt.as_bytes()));
    let _ = writeln!(
        w,
        "dispatch {}",
        v.dispatch
            .map(|d| hx(d.as_bytes()))
            .unwrap_or_else(|| "none".into())
    );
    let _ = writeln!(
        w,
        "expected_digest {}",
        v.expected_digest
            .map(|d| d.to_hex())
            .unwrap_or_else(|| "none".into())
    );
    let _ = writeln!(
        w,
        "actual_digest {}",
        v.actual_digest
            .map(|d| d.to_hex())
            .unwrap_or_else(|| "none".into())
    );
    let _ = writeln!(w, "status {}", v.status.tag());
    match &v.status {
        JournalStatus::Unavailable { reason } => {
            let _ = writeln!(w, "reason: {reason}");
        }
        JournalStatus::Missing => {
            let _ = writeln!(
                w,
                "reason: the store records a journal digest but no journal bytes were found"
            );
        }
        JournalStatus::DigestMismatch { .. } => {
            let _ = writeln!(
                w,
                "content withheld: the journal bytes do not match the digest the runtime \
                 recorded, so they are not evidence of this dispatch"
            );
        }
        JournalStatus::Corrupt {
            line_number,
            reason,
        } => {
            let _ = writeln!(
                w,
                "content withheld (line {line_number}): {reason}; unrecognized content is \
                 redacted rather than rendered as evidence"
            );
        }
        JournalStatus::VerifiedPartial | JournalStatus::VerifiedComplete => {
            if matches!(v.status, JournalStatus::VerifiedPartial) {
                let _ = writeln!(
                    w,
                    "note: the journal does not reach a terminal phase — the broker did not \
                     exit cleanly"
                );
            }
            for (i, ev) in v.events.iter().enumerate() {
                match event_detail(ev) {
                    Some(detail) => {
                        let _ = writeln!(w, "  {} {} {}", i, ev.phase_tag(), detail);
                    }
                    None => {
                        let _ = writeln!(w, "  {} {}", i, ev.phase_tag());
                    }
                }
            }
            let _ = writeln!(
                w,
                "verified: bytes match the recorded digest; verification does not \
                 independently prove each journal statement true"
            );
        }
    }
    out
}

fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Versioned JSON rendering. Same source value as the human rendering.
pub fn render_journal_json(v: &JournalView) -> String {
    let status = match &v.status {
        JournalStatus::Unavailable { reason } => {
            format!("{{\"kind\":\"unavailable\",\"reason\":{}}}", js(reason))
        }
        JournalStatus::Missing => "{\"kind\":\"missing\"}".into(),
        JournalStatus::DigestMismatch { expected, actual } => format!(
            "{{\"kind\":\"digest_mismatch\",\"expected\":{},\"actual\":{}}}",
            js(&expected.to_hex()),
            js(&actual.to_hex())
        ),
        JournalStatus::Corrupt {
            line_number,
            reason,
        } => format!(
            "{{\"kind\":\"corrupt\",\"line_number\":{line_number},\"reason\":{}}}",
            js(reason)
        ),
        JournalStatus::VerifiedPartial => "{\"kind\":\"verified_partial\"}".into(),
        JournalStatus::VerifiedComplete => "{\"kind\":\"verified_complete\"}".into(),
    };
    let events: Vec<String> = v
        .events
        .iter()
        .map(|ev| match ev {
            JournalEvent::CommitCreated(c) => format!(
                "{{\"phase\":\"commit_created\",\"commit\":{}}}",
                js(c.as_str())
            ),
            JournalEvent::RefUpdated { previous, result } => format!(
                "{{\"phase\":\"ref_updated\",\"previous\":{},\"result\":{}}}",
                js(previous.as_str()),
                js(result.as_str())
            ),
            JournalEvent::Refused(g) => {
                format!("{{\"phase\":\"refused\",\"ground\":{}}}", js(g.tag()))
            }
            other => format!("{{\"phase\":{}}}", js(other.phase_tag())),
        })
        .collect();
    format!(
        "{{\"journal_format\":{},\"attempt\":{},\"dispatch\":{},\"expected_digest\":{},\
         \"actual_digest\":{},\"status\":{},\"verified\":{},\"events\":[{}]}}",
        js(JOURNAL_FORMAT),
        js(&hx(v.attempt.as_bytes())),
        v.dispatch
            .map(|d| js(&hx(d.as_bytes())))
            .unwrap_or_else(|| "null".into()),
        v.expected_digest
            .map(|d| js(&d.to_hex()))
            .unwrap_or_else(|| "null".into()),
        v.actual_digest
            .map(|d| js(&d.to_hex()))
            .unwrap_or_else(|| "null".into()),
        status,
        v.status.verified(),
        events.join(",")
    )
}
