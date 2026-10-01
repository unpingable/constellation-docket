#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::ffi::c_void;

const PROTOCOL: &[u8] = b"docket.experimental.host-guest-pipe/v1";
const WORK_SCHEMA: &[u8] = b"docket.experimental.fixed-result-cell-work/v1";
const GUEST_BUILD: &[u8] = env!("DOCKET_STAGE1A_GUEST_BUILD").as_bytes();
const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_TEXT: usize = 128;
const MAX_ATTEMPTS: usize = 8;

global_asm!(
    r#"
.section .multiboot,"a"
.align 4
.long 0x1badb002
.long 0
.long -(0x1badb002)

.section .text.boot,"ax"
.code32
.global _start
_start:
    cli
    mov %cr0, %eax
    and $0xfffffffb, %eax
    or $0x2, %eax
    mov %eax, %cr0
    mov %cr4, %eax
    or $0x600, %eax
    mov %eax, %cr4
    mov $stack_top, %esp
    call guest_main
1:
    hlt
    jmp 1b

.section .bss.stack,"aw",@nobits
.align 16
stack_bottom:
.skip 65536
stack_top:
"#,
    options(att_syntax)
);

#[derive(Clone, Copy, Eq, PartialEq)]
struct Text {
    len: u16,
    bytes: [u8; MAX_TEXT],
}

impl Text {
    const EMPTY: Self = Self {
        len: 0,
        bytes: [0; MAX_TEXT],
    };

    fn from_slice(value: &[u8]) -> Result<Self, ()> {
        if value.len() > MAX_TEXT {
            return Err(());
        }
        let mut result = Self::EMPTY;
        result.bytes[..value.len()].copy_from_slice(value);
        result.len = value.len() as u16;
        Ok(result)
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Binding {
    attempt: Text,
    marker: Text,
    work_schema: Text,
    work: Text,
    subject: Text,
    scope: Text,
}

impl Binding {
    const EMPTY: Self = Self {
        attempt: Text::EMPTY,
        marker: Text::EMPTY,
        work_schema: Text::EMPTY,
        work: Text::EMPTY,
        subject: Text::EMPTY,
        scope: Text::EMPTY,
    };

    fn validate(&self) -> Result<(), ()> {
        for value in [
            &self.attempt,
            &self.marker,
            &self.work,
            &self.subject,
            &self.scope,
        ] {
            require_digest(value.as_slice())?;
        }
        if self.work_schema.as_slice() != WORK_SCHEMA {
            return Err(());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Verb {
    Hello,
    Execute,
    Reconcile,
}

#[derive(Clone, Copy)]
struct Request {
    verb: Verb,
    session: Text,
    sequence: u64,
    binding: Binding,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Outcome {
    Success,
    Failure,
    Indeterminate,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Empty,
    Reserved,
    Effected,
    Committed,
}

#[derive(Clone, Copy)]
struct Journal {
    phase: Phase,
    binding: Binding,
    pre_generation: u64,
    pre_identity: Text,
    post_generation: u64,
    receipt: Text,
}

impl Journal {
    const EMPTY: Self = Self {
        phase: Phase::Empty,
        binding: Binding::EMPTY,
        pre_generation: 0,
        pre_identity: Text::EMPTY,
        post_generation: 0,
        receipt: Text::EMPTY,
    };
}

#[derive(Clone, Copy)]
struct Cell {
    present: bool,
    generation: u64,
    binding: Binding,
}

impl Cell {
    const EMPTY: Self = Self {
        present: false,
        generation: 0,
        binding: Binding::EMPTY,
    };
}

struct VolatileState {
    journals: [Journal; MAX_ATTEMPTS],
    cell: Cell,
}

impl VolatileState {
    const EMPTY: Self = Self {
        journals: [Journal::EMPTY; MAX_ATTEMPTS],
        cell: Cell::EMPTY,
    };
}

enum EffectResult {
    Respond(Outcome, Text),
    DropResponse,
    Refuse,
}

const FAULT_CUT: u8 = if cfg!(stage1a_fault_after_reservation) {
    1
} else if cfg!(stage1a_fault_after_effect) {
    2
} else if cfg!(stage1a_fault_after_commit) {
    3
} else {
    0
};

#[unsafe(no_mangle)]
pub extern "C" fn guest_main() -> ! {
    serial_init();
    serial_write(0xa5);
    let mut state = VolatileState::EMPTY;
    loop {
        let hello = match read_request() {
            Ok(request)
                if request.verb == Verb::Hello
                    && request.sequence == 1
                    && require_digest(request.session.as_slice()).is_ok() =>
            {
                request
            }
            _ => halt_forever(),
        };
        if write_hello(&hello.session).is_err() {
            halt_forever();
        }
        let request = match read_request() {
            Ok(request)
                if request.verb != Verb::Hello
                    && request.sequence == 2
                    && request.session == hello.session
                    && request.binding.validate().is_ok() =>
            {
                request
            }
            _ => halt_forever(),
        };
        let result = match request.verb {
            Verb::Execute => execute(&mut state, &request.binding),
            Verb::Reconcile => reconcile(&state, &request.binding),
            Verb::Hello => EffectResult::Refuse,
        };
        match result {
            EffectResult::Respond(outcome, receipt) => {
                if write_operation(
                    request.verb,
                    &request.session,
                    &request.binding,
                    outcome,
                    &receipt,
                )
                .is_err()
                {
                    halt_forever();
                }
            }
            EffectResult::DropResponse => {}
            EffectResult::Refuse => halt_forever(),
        }
    }
}

fn execute(state: &mut VolatileState, binding: &Binding) -> EffectResult {
    if let Some(index) = find_attempt(state, binding.attempt.as_slice()) {
        let journal = state.journals[index];
        if journal.binding != *binding {
            return EffectResult::Refuse;
        }
        return classify(state, &journal);
    }
    let Some(index) = state
        .journals
        .iter()
        .position(|journal| journal.phase == Phase::Empty)
    else {
        return EffectResult::Refuse;
    };
    let pre_identity = cell_identity(&state.cell);
    state.journals[index] = Journal {
        phase: Phase::Reserved,
        binding: *binding,
        pre_generation: state.cell.generation,
        pre_identity,
        post_generation: 0,
        receipt: Text::EMPTY,
    };
    if FAULT_CUT == 1 {
        return EffectResult::DropResponse;
    }
    let Some(post_generation) = state.cell.generation.checked_add(1) else {
        return EffectResult::Refuse;
    };
    state.cell = Cell {
        present: true,
        generation: post_generation,
        binding: *binding,
    };
    if FAULT_CUT == 2 {
        return EffectResult::DropResponse;
    }
    state.journals[index].phase = Phase::Effected;
    state.journals[index].post_generation = post_generation;
    let receipt = success_receipt(binding, post_generation);
    state.journals[index].phase = Phase::Committed;
    state.journals[index].receipt = receipt;
    if FAULT_CUT == 3 {
        return EffectResult::DropResponse;
    }
    EffectResult::Respond(Outcome::Success, receipt)
}

fn reconcile(state: &VolatileState, binding: &Binding) -> EffectResult {
    let Some(index) = find_attempt(state, binding.attempt.as_slice()) else {
        return EffectResult::Respond(
            Outcome::Indeterminate,
            indeterminate_receipt(binding, b"volatile-state-empty", b"reset-or-new-launch"),
        );
    };
    let journal = state.journals[index];
    if journal.binding != *binding {
        return EffectResult::Refuse;
    }
    classify(state, &journal)
}

fn find_attempt(state: &VolatileState, attempt: &[u8]) -> Option<usize> {
    state.journals.iter().position(|journal| {
        journal.phase != Phase::Empty && journal.binding.attempt.as_slice() == attempt
    })
}

fn classify(state: &VolatileState, journal: &Journal) -> EffectResult {
    match journal.phase {
        Phase::Committed => EffectResult::Respond(Outcome::Success, journal.receipt),
        Phase::Effected => EffectResult::Respond(
            Outcome::Success,
            success_receipt(&journal.binding, journal.post_generation),
        ),
        Phase::Reserved => {
            let current_identity = cell_identity(&state.cell);
            if current_identity == journal.pre_identity {
                EffectResult::Respond(Outcome::Failure, failure_receipt(journal))
            } else if state.cell.present
                && state.cell.generation == journal.pre_generation.saturating_add(1)
                && state.cell.binding == journal.binding
            {
                EffectResult::Respond(
                    Outcome::Success,
                    success_receipt(&journal.binding, state.cell.generation),
                )
            } else {
                EffectResult::Respond(
                    Outcome::Indeterminate,
                    indeterminate_receipt(
                        &journal.binding,
                        current_identity.as_slice(),
                        b"reserved-evidence-disagrees",
                    ),
                )
            }
        }
        Phase::Empty => EffectResult::Refuse,
    }
}

fn success_receipt(binding: &Binding, generation: u64) -> Text {
    transcript_digest(
        b"simulated-guest-success-receipt/v1",
        &[
            binding.attempt.as_slice(),
            binding.marker.as_slice(),
            binding.work_schema.as_slice(),
            binding.work.as_slice(),
            binding.subject.as_slice(),
            binding.scope.as_slice(),
            &generation.to_be_bytes(),
            b"success",
        ],
    )
}

fn failure_receipt(journal: &Journal) -> Text {
    transcript_digest(
        b"simulated-guest-failure-receipt/v1",
        &[
            journal.binding.attempt.as_slice(),
            journal.binding.marker.as_slice(),
            journal.binding.work_schema.as_slice(),
            journal.binding.work.as_slice(),
            journal.binding.subject.as_slice(),
            journal.binding.scope.as_slice(),
            &journal.pre_generation.to_be_bytes(),
            journal.pre_identity.as_slice(),
            b"failure",
        ],
    )
}

fn indeterminate_receipt(binding: &Binding, evidence: &[u8], reason: &[u8]) -> Text {
    transcript_digest(
        b"simulated-guest-indeterminate-evidence/v1",
        &[
            binding.attempt.as_slice(),
            binding.marker.as_slice(),
            binding.work_schema.as_slice(),
            binding.work.as_slice(),
            binding.subject.as_slice(),
            binding.scope.as_slice(),
            evidence,
            reason,
        ],
    )
}

fn cell_identity(cell: &Cell) -> Text {
    if !cell.present {
        return Text::from_slice(b"missing").unwrap_or(Text::EMPTY);
    }
    transcript_digest(
        b"vm-volatile-cell-evidence/v1",
        &[
            &cell.generation.to_be_bytes(),
            cell.binding.attempt.as_slice(),
            cell.binding.marker.as_slice(),
            cell.binding.work_schema.as_slice(),
            cell.binding.work.as_slice(),
            cell.binding.subject.as_slice(),
            cell.binding.scope.as_slice(),
        ],
    )
}

fn read_request() -> Result<Request, ()> {
    let length =
        u32::from_be_bytes([serial_read(), serial_read(), serial_read(), serial_read()]) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(());
    }
    let mut frame = [0_u8; MAX_FRAME_BYTES];
    for byte in &mut frame[..length] {
        *byte = serial_read();
    }
    parse_request(&frame[..length])
}

#[derive(Clone, Copy)]
struct Fields {
    seen: u16,
    verb: Text,
    protocol: Text,
    session: Text,
    sequence: u64,
    binding: Binding,
}

impl Fields {
    const EMPTY: Self = Self {
        seen: 0,
        verb: Text::EMPTY,
        protocol: Text::EMPTY,
        session: Text::EMPTY,
        sequence: 0,
        binding: Binding::EMPTY,
    };
}

fn parse_request(input: &[u8]) -> Result<Request, ()> {
    const VERB: u16 = 1 << 0;
    const PROTOCOL_FIELD: u16 = 1 << 1;
    const SESSION: u16 = 1 << 2;
    const SEQUENCE: u16 = 1 << 3;
    const ATTEMPT: u16 = 1 << 4;
    const MARKER: u16 = 1 << 5;
    const WORK_SCHEMA_FIELD: u16 = 1 << 6;
    const WORK: u16 = 1 << 7;
    const SUBJECT: u16 = 1 << 8;
    const SCOPE: u16 = 1 << 9;
    const HELLO_FIELDS: u16 = VERB | PROTOCOL_FIELD | SESSION | SEQUENCE;
    const OPERATION_FIELDS: u16 =
        HELLO_FIELDS | ATTEMPT | MARKER | WORK_SCHEMA_FIELD | WORK | SUBJECT | SCOPE;

    let mut cursor = JsonCursor { input, offset: 0 };
    let mut fields = Fields::EMPTY;
    cursor.byte(b'{')?;
    loop {
        cursor.space();
        if cursor.take_if(b'}') {
            break;
        }
        let key: Text = cursor.string()?;
        cursor.space();
        cursor.byte(b':')?;
        cursor.space();
        let (bit, is_number) = match key.as_slice() {
            b"verb" => (VERB, false),
            b"protocol" => (PROTOCOL_FIELD, false),
            b"session" => (SESSION, false),
            b"sequence" => (SEQUENCE, true),
            b"attempt" => (ATTEMPT, false),
            b"marker" => (MARKER, false),
            b"work_schema" => (WORK_SCHEMA_FIELD, false),
            b"work" => (WORK, false),
            b"subject" => (SUBJECT, false),
            b"scope" => (SCOPE, false),
            _ => return Err(()),
        };
        if fields.seen & bit != 0 {
            return Err(());
        }
        fields.seen |= bit;
        if is_number {
            fields.sequence = cursor.number()?;
        } else {
            let value: Text = cursor.string()?;
            match bit {
                VERB => fields.verb = value,
                PROTOCOL_FIELD => fields.protocol = value,
                SESSION => fields.session = value,
                ATTEMPT => fields.binding.attempt = value,
                MARKER => fields.binding.marker = value,
                WORK_SCHEMA_FIELD => fields.binding.work_schema = value,
                WORK => fields.binding.work = value,
                SUBJECT => fields.binding.subject = value,
                SCOPE => fields.binding.scope = value,
                _ => return Err(()),
            }
        }
        cursor.space();
        if cursor.take_if(b',') {
            continue;
        }
        cursor.byte(b'}')?;
        break;
    }
    cursor.space();
    if cursor.offset != input.len() || fields.protocol.as_slice() != PROTOCOL {
        return Err(());
    }
    let verb = match fields.verb.as_slice() {
        b"HELLO" if fields.seen == HELLO_FIELDS => Verb::Hello,
        b"EXECUTE" if fields.seen == OPERATION_FIELDS => Verb::Execute,
        b"RECONCILE" if fields.seen == OPERATION_FIELDS => Verb::Reconcile,
        _ => return Err(()),
    };
    Ok(Request {
        verb,
        session: fields.session,
        sequence: fields.sequence,
        binding: fields.binding,
    })
}

struct JsonCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl JsonCursor<'_> {
    fn space(&mut self) {
        while matches!(
            self.input.get(self.offset),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.offset += 1;
        }
    }

    fn byte(&mut self, expected: u8) -> Result<(), ()> {
        self.space();
        if self.input.get(self.offset) != Some(&expected) {
            return Err(());
        }
        self.offset += 1;
        Ok(())
    }

    fn take_if(&mut self, expected: u8) -> bool {
        self.space();
        if self.input.get(self.offset) == Some(&expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn string(&mut self) -> Result<Text, ()> {
        self.byte(b'"')?;
        let mut output = Text::EMPTY;
        loop {
            let byte = *self.input.get(self.offset).ok_or(())?;
            self.offset += 1;
            if byte == b'"' {
                return Ok(output);
            }
            let decoded = if byte == b'\\' {
                let escaped = *self.input.get(self.offset).ok_or(())?;
                self.offset += 1;
                match escaped {
                    b'"' | b'\\' | b'/' => escaped,
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    _ => return Err(()),
                }
            } else if (0x20..=0x7e).contains(&byte) {
                byte
            } else {
                return Err(());
            };
            let index = usize::from(output.len);
            if index == MAX_TEXT {
                return Err(());
            }
            output.bytes[index] = decoded;
            output.len += 1;
        }
    }

    fn number(&mut self) -> Result<u64, ()> {
        let start = self.offset;
        let mut value = 0_u64;
        while let Some(byte @ b'0'..=b'9') = self.input.get(self.offset).copied() {
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(u64::from(byte - b'0')))
                .ok_or(())?;
            self.offset += 1;
        }
        if self.offset == start {
            return Err(());
        }
        Ok(value)
    }
}

struct JsonWriter {
    bytes: [u8; 4096],
    length: usize,
}

impl JsonWriter {
    fn new() -> Self {
        Self {
            bytes: [0; 4096],
            length: 0,
        }
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), ()> {
        let end = self.length.checked_add(value.len()).ok_or(())?;
        if end > self.bytes.len() {
            return Err(());
        }
        self.bytes[self.length..end].copy_from_slice(value);
        self.length = end;
        Ok(())
    }

    fn string(&mut self, value: &[u8]) -> Result<(), ()> {
        self.raw(b"\"")?;
        for byte in value {
            if !(0x20..=0x7e).contains(byte) || matches!(byte, b'"' | b'\\') {
                return Err(());
            }
            self.raw(&[*byte])?;
        }
        self.raw(b"\"")
    }

    fn field(&mut self, key: &[u8], value: &[u8], first: bool) -> Result<(), ()> {
        if !first {
            self.raw(b",")?;
        }
        self.string(key)?;
        self.raw(b":")?;
        self.string(value)
    }
}

fn write_hello(session: &Text) -> Result<(), ()> {
    let mut writer = JsonWriter::new();
    writer.raw(b"{")?;
    writer.field(b"verb", b"HELLO", true)?;
    writer.field(b"protocol", PROTOCOL, false)?;
    writer.field(b"session", session.as_slice(), false)?;
    writer.raw(b",\"sequence\":1")?;
    writer.field(b"simulator_build", GUEST_BUILD, false)?;
    writer.raw(b"}")?;
    write_frame(&writer.bytes[..writer.length])
}

fn write_operation(
    verb: Verb,
    session: &Text,
    binding: &Binding,
    outcome: Outcome,
    receipt: &Text,
) -> Result<(), ()> {
    let mut writer = JsonWriter::new();
    writer.raw(b"{")?;
    writer.field(
        b"verb",
        match verb {
            Verb::Execute => b"EXECUTE",
            Verb::Reconcile => b"RECONCILE",
            Verb::Hello => return Err(()),
        },
        true,
    )?;
    writer.field(b"protocol", PROTOCOL, false)?;
    writer.field(b"session", session.as_slice(), false)?;
    writer.raw(b",\"sequence\":2")?;
    writer.field(b"attempt", binding.attempt.as_slice(), false)?;
    writer.field(b"marker", binding.marker.as_slice(), false)?;
    writer.field(b"work_schema", binding.work_schema.as_slice(), false)?;
    writer.field(b"work", binding.work.as_slice(), false)?;
    writer.field(b"subject", binding.subject.as_slice(), false)?;
    writer.field(b"scope", binding.scope.as_slice(), false)?;
    writer.field(
        b"outcome",
        match outcome {
            Outcome::Success => b"success",
            Outcome::Failure => b"failure",
            Outcome::Indeterminate => b"indeterminate",
        },
        false,
    )?;
    writer.field(b"receipt", receipt.as_slice(), false)?;
    writer.raw(b"}")?;
    write_frame(&writer.bytes[..writer.length])
}

fn write_frame(body: &[u8]) -> Result<(), ()> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(());
    }
    for byte in (body.len() as u32).to_be_bytes() {
        serial_write(byte);
    }
    for byte in body {
        serial_write(*byte);
    }
    Ok(())
}

fn require_digest(value: &[u8]) -> Result<(), ()> {
    if value.len() != 71 || &value[..7] != b"sha256:" {
        return Err(());
    }
    if value[7..]
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(())
    }
}

fn transcript_digest(domain: &[u8], fields: &[&[u8]]) -> Text {
    let mut digest = Sha256::new();
    digest.update(b"docket\0experimental-stage0\0v1\0");
    digest.update(&(domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        digest.update(&(field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    let hash = digest.finish();
    let mut output = Text::EMPTY;
    output.bytes[..7].copy_from_slice(b"sha256:");
    for (index, byte) in hash.iter().enumerate() {
        output.bytes[7 + index * 2] = hex(byte >> 4);
        output.bytes[8 + index * 2] = hex(byte & 0x0f);
    }
    output.len = 71;
    output
}

fn hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    used: usize,
    length: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            used: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        while !bytes.is_empty() {
            let count = core::cmp::min(64 - self.used, bytes.len());
            self.block[self.used..self.used + count].copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];
            if self.used == 64 {
                self.compress();
                self.used = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_length = self.length.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > 56 {
            self.block[self.used..].fill(0);
            self.compress();
            self.block.fill(0);
        } else {
            self.block[self.used..56].fill(0);
        }
        self.block[56..64].copy_from_slice(&bit_length.to_be_bytes());
        self.compress();
        let mut output = [0_u8; 32];
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(&mut self) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0_u32; 64];
        for (index, chunk) in self.block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}

fn serial_init() {
    unsafe {
        out(0x3f9, 0);
        out(0x3fb, 0x80);
        out(0x3f8, 1);
        out(0x3f9, 0);
        out(0x3fb, 3);
        out(0x3fa, 0xc7);
        out(0x3fc, 0x0b);
    }
}

fn serial_read() -> u8 {
    while unsafe { input(0x3fd) } & 1 == 0 {
        core::hint::spin_loop();
    }
    unsafe { input(0x3f8) }
}

fn serial_write(value: u8) {
    while unsafe { input(0x3fd) } & 0x20 == 0 {
        core::hint::spin_loop();
    }
    unsafe { out(0x3f8, value) }
}

unsafe fn out(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

unsafe fn input(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

fn halt_forever() -> ! {
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    length: usize,
) -> *mut c_void {
    let destination = destination.cast::<u8>();
    let source = source.cast::<u8>();
    for index in 0..length {
        unsafe {
            destination
                .add(index)
                .write_volatile(source.add(index).read_volatile());
        }
    }
    destination.cast::<c_void>()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(destination: *mut c_void, value: i32, length: usize) -> *mut c_void {
    let destination = destination.cast::<u8>();
    for index in 0..length {
        unsafe { destination.add(index).write_volatile(value as u8) };
    }
    destination.cast::<c_void>()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, length: usize) -> i32 {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for index in 0..length {
        let (left_byte, right_byte) = unsafe {
            (
                left.add(index).read_volatile(),
                right.add(index).read_volatile(),
            )
        };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt_forever()
}
