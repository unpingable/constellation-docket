//! Closed, bounded pipe protocol for the Stage-0 simulated guest.

use gwr_runtime::governed_loop::{require_digest, ExecutorDispatchWireV1};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};

pub const GUEST_PROTOCOL_V1: &str = "docket.experimental.host-guest-pipe/v1";
pub const STAGE0_WORK_SCHEMA_V1: &str = "docket.experimental.fixed-result-cell-work/v1";
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkBindingV1 {
    pub attempt: String,
    pub marker: String,
    pub work_schema: String,
    pub work: String,
    pub subject: String,
    pub scope: String,
}

impl From<&ExecutorDispatchWireV1> for WorkBindingV1 {
    fn from(value: &ExecutorDispatchWireV1) -> Self {
        Self {
            attempt: value.attempt.clone(),
            marker: value.marker.clone(),
            work_schema: value.work_schema.clone(),
            work: value.work.clone(),
            subject: value.subject.clone(),
            scope: value.scope.clone(),
        }
    }
}

impl WorkBindingV1 {
    pub fn validate(&self) -> Result<(), String> {
        for (value, label) in [
            (&self.attempt, "stage0 attempt"),
            (&self.marker, "stage0 marker"),
            (&self.work, "stage0 work"),
            (&self.subject, "stage0 subject"),
            (&self.scope, "stage0 scope"),
        ] {
            require_digest(value, label)?;
        }
        if self.work_schema != STAGE0_WORK_SCHEMA_V1 {
            return Err("stage0-work-schema-refusal".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", deny_unknown_fields)]
pub enum GuestRequestV1 {
    #[serde(rename = "HELLO")]
    Hello {
        protocol: String,
        session: String,
        sequence: u64,
    },
    #[serde(rename = "EXECUTE")]
    Execute {
        protocol: String,
        session: String,
        sequence: u64,
        attempt: String,
        marker: String,
        work_schema: String,
        work: String,
        subject: String,
        scope: String,
    },
    #[serde(rename = "RECONCILE")]
    Reconcile {
        protocol: String,
        session: String,
        sequence: u64,
        attempt: String,
        marker: String,
        work_schema: String,
        work: String,
        subject: String,
        scope: String,
    },
}

impl GuestRequestV1 {
    pub fn hello(session: String) -> Self {
        Self::Hello {
            protocol: GUEST_PROTOCOL_V1.to_owned(),
            session,
            sequence: 1,
        }
    }

    pub fn operation(operation: OperationV1, session: String, binding: &WorkBindingV1) -> Self {
        match operation {
            OperationV1::Execute => Self::Execute {
                protocol: GUEST_PROTOCOL_V1.to_owned(),
                session,
                sequence: 2,
                attempt: binding.attempt.clone(),
                marker: binding.marker.clone(),
                work_schema: binding.work_schema.clone(),
                work: binding.work.clone(),
                subject: binding.subject.clone(),
                scope: binding.scope.clone(),
            },
            OperationV1::Reconcile => Self::Reconcile {
                protocol: GUEST_PROTOCOL_V1.to_owned(),
                session,
                sequence: 2,
                attempt: binding.attempt.clone(),
                marker: binding.marker.clone(),
                work_schema: binding.work_schema.clone(),
                work: binding.work.clone(),
                subject: binding.subject.clone(),
                scope: binding.scope.clone(),
            },
        }
    }

    pub fn operation_parts(&self) -> Result<(OperationV1, &str, u64, WorkBindingV1), String> {
        let (operation, protocol, session, sequence, binding) = match self {
            Self::Execute {
                protocol,
                session,
                sequence,
                attempt,
                marker,
                work_schema,
                work,
                subject,
                scope,
            } => (
                OperationV1::Execute,
                protocol,
                session,
                *sequence,
                WorkBindingV1 {
                    attempt: attempt.clone(),
                    marker: marker.clone(),
                    work_schema: work_schema.clone(),
                    work: work.clone(),
                    subject: subject.clone(),
                    scope: scope.clone(),
                },
            ),
            Self::Reconcile {
                protocol,
                session,
                sequence,
                attempt,
                marker,
                work_schema,
                work,
                subject,
                scope,
            } => (
                OperationV1::Reconcile,
                protocol,
                session,
                *sequence,
                WorkBindingV1 {
                    attempt: attempt.clone(),
                    marker: marker.clone(),
                    work_schema: work_schema.clone(),
                    work: work.clone(),
                    subject: subject.clone(),
                    scope: scope.clone(),
                },
            ),
            Self::Hello { .. } => return Err("stage0-out-of-sequence-hello".to_owned()),
        };
        require_protocol_session(protocol, session)?;
        binding.validate()?;
        Ok((operation, session, sequence, binding))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationV1 {
    Execute,
    Reconcile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestOutcomeV1 {
    Success,
    Failure,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", deny_unknown_fields)]
pub enum GuestResponseV1 {
    #[serde(rename = "HELLO")]
    Hello {
        protocol: String,
        session: String,
        sequence: u64,
        simulator_build: String,
    },
    #[serde(rename = "EXECUTE")]
    Execute {
        protocol: String,
        session: String,
        sequence: u64,
        attempt: String,
        marker: String,
        work_schema: String,
        work: String,
        subject: String,
        scope: String,
        outcome: GuestOutcomeV1,
        receipt: String,
    },
    #[serde(rename = "RECONCILE")]
    Reconcile {
        protocol: String,
        session: String,
        sequence: u64,
        attempt: String,
        marker: String,
        work_schema: String,
        work: String,
        subject: String,
        scope: String,
        outcome: GuestOutcomeV1,
        receipt: String,
    },
}

impl GuestResponseV1 {
    pub fn hello(session: String, simulator_build: String) -> Self {
        Self::Hello {
            protocol: GUEST_PROTOCOL_V1.to_owned(),
            session,
            sequence: 1,
            simulator_build,
        }
    }

    pub fn operation(
        operation: OperationV1,
        session: String,
        binding: &WorkBindingV1,
        outcome: GuestOutcomeV1,
        receipt: String,
    ) -> Self {
        match operation {
            OperationV1::Execute => Self::Execute {
                protocol: GUEST_PROTOCOL_V1.to_owned(),
                session,
                sequence: 2,
                attempt: binding.attempt.clone(),
                marker: binding.marker.clone(),
                work_schema: binding.work_schema.clone(),
                work: binding.work.clone(),
                subject: binding.subject.clone(),
                scope: binding.scope.clone(),
                outcome,
                receipt,
            },
            OperationV1::Reconcile => Self::Reconcile {
                protocol: GUEST_PROTOCOL_V1.to_owned(),
                session,
                sequence: 2,
                attempt: binding.attempt.clone(),
                marker: binding.marker.clone(),
                work_schema: binding.work_schema.clone(),
                work: binding.work.clone(),
                subject: binding.subject.clone(),
                scope: binding.scope.clone(),
                outcome,
                receipt,
            },
        }
    }
}

pub fn validate_hello(
    response: &GuestResponseV1,
    session: &str,
    simulator_build: &str,
) -> Result<(), String> {
    match response {
        GuestResponseV1::Hello {
            protocol,
            session: actual_session,
            sequence,
            simulator_build: actual_build,
        } if protocol == GUEST_PROTOCOL_V1
            && actual_session == session
            && *sequence == 1
            && actual_build == simulator_build =>
        {
            Ok(())
        }
        _ => Err("stage0-hello-response-substitution".to_owned()),
    }
}

pub fn validate_operation_response(
    response: GuestResponseV1,
    operation: OperationV1,
    session: &str,
    binding: &WorkBindingV1,
) -> Result<(GuestOutcomeV1, String), String> {
    let (actual_operation, protocol, actual_session, sequence, actual, outcome, receipt) =
        match response {
            GuestResponseV1::Execute {
                protocol,
                session,
                sequence,
                attempt,
                marker,
                work_schema,
                work,
                subject,
                scope,
                outcome,
                receipt,
            } => (
                OperationV1::Execute,
                protocol,
                session,
                sequence,
                WorkBindingV1 {
                    attempt,
                    marker,
                    work_schema,
                    work,
                    subject,
                    scope,
                },
                outcome,
                receipt,
            ),
            GuestResponseV1::Reconcile {
                protocol,
                session,
                sequence,
                attempt,
                marker,
                work_schema,
                work,
                subject,
                scope,
                outcome,
                receipt,
            } => (
                OperationV1::Reconcile,
                protocol,
                session,
                sequence,
                WorkBindingV1 {
                    attempt,
                    marker,
                    work_schema,
                    work,
                    subject,
                    scope,
                },
                outcome,
                receipt,
            ),
            GuestResponseV1::Hello { .. } => {
                return Err("stage0-stale-or-out-of-order-response".to_owned())
            }
        };
    if actual_operation != operation
        || protocol != GUEST_PROTOCOL_V1
        || actual_session != session
        || sequence != 2
        || actual != *binding
    {
        return Err("stage0-operation-response-substitution".to_owned());
    }
    require_digest(&receipt, "stage0 guest receipt")?;
    Ok((outcome, receipt))
}

pub fn parse_hello(request: GuestRequestV1) -> Result<String, String> {
    match request {
        GuestRequestV1::Hello {
            protocol,
            session,
            sequence,
        } => {
            require_protocol_session(&protocol, &session)?;
            if sequence != 1 {
                return Err("stage0-hello-sequence".to_owned());
            }
            Ok(session)
        }
        _ => Err("stage0-first-verb-not-hello".to_owned()),
    }
}

fn require_protocol_session(protocol: &str, session: &str) -> Result<(), String> {
    if protocol != GUEST_PROTOCOL_V1 {
        return Err("stage0-protocol-version-refusal".to_owned());
    }
    require_digest(session, "stage0 session")
}

pub fn write_frame<T: Serialize, W: Write>(writer: &mut W, value: &T) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|error| format!("stage0-frame-json:{error}"))?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err("stage0-frame-size".to_owned());
    }
    let length = u32::try_from(body.len()).map_err(|_| "stage0-frame-size".to_owned())?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(&body))
        .and_then(|()| writer.flush())
        .map_err(|error| format!("stage0-frame-write:{error}"))
}

pub fn read_frame<T: DeserializeOwned, R: Read>(reader: &mut R) -> Result<T, String> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|error| format!("stage0-frame-prefix:{error}"))?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| "stage0-frame-size".to_owned())?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("stage0-frame-size".to_owned());
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("stage0-frame-body:{error}"))?;
    serde_json::from_slice(&body).map_err(|error| format!("stage0-frame-json:{error}"))
}

pub fn require_eof<R: Read>(reader: &mut R) -> Result<(), String> {
    let mut extra = [0_u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err("stage0-duplicate-response".to_owned()),
        Err(error) => Err(format!("stage0-response-eof:{error}")),
    }
}

pub fn transcript_digest(domain: &str, fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"docket\0experimental-stage0\0v1\0");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((fields.len() as u64).to_be_bytes());
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    format!("sha256:{}", lower_hex(&hasher.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn digest(label: &str) -> String {
        transcript_digest("protocol-test/v1", &[label.as_bytes()])
    }

    fn binding() -> WorkBindingV1 {
        WorkBindingV1 {
            attempt: digest("attempt"),
            marker: digest("marker"),
            work_schema: STAGE0_WORK_SCHEMA_V1.to_owned(),
            work: digest("work"),
            subject: digest("subject"),
            scope: digest("scope"),
        }
    }

    #[test]
    fn framing_round_trips_hello_and_execute() {
        let session = digest("session");
        for request in [
            GuestRequestV1::hello(session.clone()),
            GuestRequestV1::operation(OperationV1::Execute, session.clone(), &binding()),
        ] {
            let mut bytes = Vec::new();
            write_frame(&mut bytes, &request).unwrap();
            let decoded: GuestRequestV1 = read_frame(&mut Cursor::new(bytes)).unwrap();
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn hostile_frames_refuse_before_unbounded_allocation() {
        let malformed = b"{";
        let mut malformed_frame = (malformed.len() as u32).to_be_bytes().to_vec();
        malformed_frame.extend_from_slice(malformed);
        assert!(read_frame::<GuestRequestV1, _>(&mut Cursor::new(malformed_frame)).is_err());

        let truncated = [0_u8, 0, 0, 8, b'{'];
        assert!(read_frame::<GuestRequestV1, _>(&mut Cursor::new(truncated)).is_err());

        let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame::<GuestRequestV1, _>(&mut Cursor::new(oversized)).unwrap_err(),
            "stage0-frame-size"
        );
    }

    #[test]
    fn closed_verb_set_unknown_and_duplicate_fields_refuse() {
        let session = digest("session");
        let unknown = format!(
            "{{\"verb\":\"RUN\",\"protocol\":\"{GUEST_PROTOCOL_V1}\",\"session\":\"{session}\",\"sequence\":1}}"
        );
        assert!(serde_json::from_str::<GuestRequestV1>(&unknown).is_err());

        let duplicate = format!(
            "{{\"verb\":\"HELLO\",\"protocol\":\"{GUEST_PROTOCOL_V1}\",\"session\":\"{session}\",\"session\":\"{}\",\"sequence\":1}}",
            digest("other-session")
        );
        assert!(serde_json::from_str::<GuestRequestV1>(&duplicate).is_err());

        for verb in ["HELLO", "EXECUTE", "RECONCILE"] {
            assert!(serde_json::to_string(&match verb {
                "HELLO" => GuestRequestV1::hello(session.clone()),
                "EXECUTE" =>
                    GuestRequestV1::operation(OperationV1::Execute, session.clone(), &binding(),),
                _ =>
                    GuestRequestV1::operation(OperationV1::Reconcile, session.clone(), &binding(),),
            })
            .unwrap()
            .contains(&format!("\"verb\":\"{verb}\"")));
        }
    }

    #[test]
    fn wrong_version_and_out_of_sequence_requests_refuse() {
        let session = digest("session");
        assert!(parse_hello(GuestRequestV1::Hello {
            protocol: "docket.experimental.host-guest-pipe/v2".to_owned(),
            session: session.clone(),
            sequence: 1,
        })
        .is_err());
        assert!(parse_hello(GuestRequestV1::Hello {
            protocol: GUEST_PROTOCOL_V1.to_owned(),
            session: session.clone(),
            sequence: 2,
        })
        .is_err());
        assert!(parse_hello(GuestRequestV1::operation(
            OperationV1::Execute,
            session,
            &binding(),
        ))
        .is_err());
    }

    #[test]
    fn every_response_binding_substitution_refuses() {
        let session = digest("session");
        let binding = binding();
        let receipt = digest("receipt");
        let response = GuestResponseV1::operation(
            OperationV1::Execute,
            session.clone(),
            &binding,
            GuestOutcomeV1::Success,
            receipt,
        );
        assert!(validate_operation_response(
            response.clone(),
            OperationV1::Execute,
            &session,
            &binding,
        )
        .is_ok());

        for field in [
            "attempt",
            "marker",
            "work",
            "work_schema",
            "subject",
            "scope",
        ] {
            let mut value = serde_json::to_value(&response).unwrap();
            value[field] = serde_json::Value::String(if field == "work_schema" {
                "substituted-work/v1".to_owned()
            } else {
                digest(&format!("changed-{field}"))
            });
            let changed: GuestResponseV1 = serde_json::from_value(value).unwrap();
            assert!(
                validate_operation_response(changed, OperationV1::Execute, &session, &binding,)
                    .is_err(),
                "{field}"
            );
        }

        let mut stale = serde_json::to_value(&response).unwrap();
        stale["session"] = serde_json::Value::String(digest("stale"));
        assert!(validate_operation_response(
            serde_json::from_value(stale).unwrap(),
            OperationV1::Execute,
            &session,
            &binding,
        )
        .is_err());
        assert!(validate_operation_response(
            GuestResponseV1::hello(session.clone(), digest("build")),
            OperationV1::Execute,
            &session,
            &binding,
        )
        .is_err());
    }

    #[test]
    fn duplicate_response_bytes_are_rejected() {
        assert!(require_eof(&mut Cursor::new([1_u8])).is_err());
        assert!(require_eof(&mut Cursor::new([])).is_ok());
    }

    #[derive(Deserialize)]
    struct HostileCorpus {
        schema: String,
        request_cases: Vec<RequestCase>,
        frame_cases: Vec<FrameCase>,
    }

    #[derive(Deserialize)]
    struct RequestCase {
        name: String,
        expect: String,
        input: String,
    }

    #[derive(Deserialize)]
    struct FrameCase {
        name: String,
        expect: String,
        hex: String,
    }

    fn request_is_semantically_valid(request: GuestRequestV1) -> bool {
        match request {
            request @ GuestRequestV1::Hello { .. } => parse_hello(request).is_ok(),
            request => request
                .operation_parts()
                .map(|(_, _, sequence, _)| sequence == 2)
                .unwrap_or(false),
        }
    }

    #[test]
    fn fixed_hostile_protocol_corpus_passes() {
        let corpus: HostileCorpus = serde_json::from_str(include_str!(
            "../../../../conformance/host-guest-stage0-v1/corpus.json"
        ))
        .unwrap();
        assert_eq!(
            corpus.schema,
            "docket.experimental.host-guest-pipe-corpus/v1"
        );

        for case in corpus.request_cases {
            let decoded = serde_json::from_str::<GuestRequestV1>(&case.input);
            match case.expect.as_str() {
                "accept" => assert!(
                    decoded.map(request_is_semantically_valid).unwrap_or(false),
                    "{}",
                    case.name
                ),
                "decode-refusal" => assert!(decoded.is_err(), "{}", case.name),
                "semantic-refusal" => assert!(
                    !decoded.map(request_is_semantically_valid).unwrap_or(false),
                    "{}",
                    case.name
                ),
                other => panic!("unknown corpus expectation {other}"),
            }
        }

        for case in corpus.frame_cases {
            assert_eq!(case.expect, "refusal", "{}", case.name);
            let bytes = case
                .hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            let result: Result<GuestRequestV1, _> = read_frame(&mut Cursor::new(bytes));
            assert!(result.is_err(), "{}", case.name);
        }
    }
}
