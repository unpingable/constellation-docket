#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::ffi::c_void;

const PROTOCOL: &[u8] = b"docket.experimental.host-guest-pipe/v1";
const WORK_SCHEMA: &[u8] = b"docket.experimental.fixed-result-cell-work/v1";
const GUEST_BUILD: &[u8] = env!("DOCKET_STAGE1B_GUEST_BUILD").as_bytes();
const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_TEXT: usize = 128;
const MAX_ATTEMPTS: usize = 8;
const JOURNAL_RECORDS: usize = MAX_ATTEMPTS * 3;
const RECORD_BYTES: usize = 1024;
const JOURNAL_START_SECTOR: u64 = 2;
const CELL_START_SECTOR: u64 = 64;

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
.skip 131072
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

struct PersistentState {
    journals: [Journal; MAX_ATTEMPTS],
    cells: [Cell; MAX_ATTEMPTS],
    journal_records: usize,
    cell_records: usize,
    corrupt: bool,
}

impl PersistentState {
    const EMPTY: Self = Self {
        journals: [Journal::EMPTY; MAX_ATTEMPTS],
        cells: [Cell::EMPTY; MAX_ATTEMPTS],
        journal_records: 0,
        cell_records: 0,
        corrupt: false,
    };

    fn current_cell(&self) -> Cell {
        if self.cell_records == 0 {
            Cell::EMPTY
        } else {
            self.cells[self.cell_records - 1]
        }
    }
}

enum EffectResult {
    Respond(Outcome, Text),
    DropResponse,
    Refuse,
}

const FAULT_CUT: u8 = if cfg!(stage1b_fault_before_reservation) {
    1
} else if cfg!(stage1b_fault_after_reservation) {
    2
} else if cfg!(stage1b_fault_after_effect) {
    3
} else if cfg!(stage1b_fault_after_commit) {
    4
} else {
    0
};

#[unsafe(no_mangle)]
pub extern "C" fn guest_main() -> ! {
    serial_init();
    let mut queue = QueueMemory::new();
    let mut block = match BlockDevice::initialize(&mut queue) {
        Ok(block) => block,
        Err(()) => halt_forever(),
    };
    let mut state = load_state(&mut block);
    serial_write(0xa5);
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
            Verb::Execute => execute(&mut state, &mut block, &request.binding),
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

fn execute(
    state: &mut PersistentState,
    block: &mut BlockDevice<'_>,
    binding: &Binding,
) -> EffectResult {
    if state.corrupt {
        return EffectResult::Refuse;
    }
    if let Some(index) = find_attempt(state, binding.attempt.as_slice()) {
        let journal = state.journals[index];
        if journal.binding != *binding {
            return EffectResult::Refuse;
        }
        return classify(state, &journal);
    }
    if FAULT_CUT == 1 {
        return cut_reached();
    }
    let Some(index) = state
        .journals
        .iter()
        .position(|journal| journal.phase == Phase::Empty)
    else {
        return EffectResult::Refuse;
    };
    let current = state.current_cell();
    let pre_identity = cell_identity(&current);
    state.journals[index] = Journal {
        phase: Phase::Reserved,
        binding: *binding,
        pre_generation: current.generation,
        pre_identity,
        post_generation: 0,
        receipt: Text::EMPTY,
    };
    if append_journal(block, state, index).is_err() {
        state.corrupt = true;
        return EffectResult::Refuse;
    }
    if FAULT_CUT == 2 {
        return cut_reached();
    }
    let Some(post_generation) = current.generation.checked_add(1) else {
        return EffectResult::Refuse;
    };
    let cell = Cell {
        present: true,
        generation: post_generation,
        binding: *binding,
    };
    if append_cell(block, state, cell).is_err() {
        state.corrupt = true;
        return EffectResult::Refuse;
    }
    if FAULT_CUT == 3 {
        return cut_reached();
    }
    state.journals[index].phase = Phase::Effected;
    state.journals[index].post_generation = post_generation;
    if append_journal(block, state, index).is_err() {
        state.corrupt = true;
        return EffectResult::Refuse;
    }
    let receipt = success_receipt(binding, post_generation);
    state.journals[index].phase = Phase::Committed;
    state.journals[index].receipt = receipt;
    if append_journal(block, state, index).is_err() {
        state.corrupt = true;
        return EffectResult::Refuse;
    }
    if FAULT_CUT == 4 {
        return cut_reached();
    }
    EffectResult::Respond(Outcome::Success, receipt)
}

fn cut_reached() -> EffectResult {
    serial_write(0x5a);
    EffectResult::DropResponse
}

fn reconcile(state: &PersistentState, binding: &Binding) -> EffectResult {
    if state.corrupt {
        return EffectResult::Respond(
            Outcome::Indeterminate,
            indeterminate_receipt(binding, b"raw-state-corrupt", b"journal-or-cell-corrupt"),
        );
    }
    let Some(index) = find_attempt(state, binding.attempt.as_slice()) else {
        return EffectResult::Refuse;
    };
    let journal = state.journals[index];
    if journal.binding != *binding {
        return EffectResult::Refuse;
    }
    classify(state, &journal)
}

fn find_attempt(state: &PersistentState, attempt: &[u8]) -> Option<usize> {
    state.journals.iter().position(|journal| {
        journal.phase != Phase::Empty && journal.binding.attempt.as_slice() == attempt
    })
}

fn classify(state: &PersistentState, journal: &Journal) -> EffectResult {
    match journal.phase {
        Phase::Committed => EffectResult::Respond(Outcome::Success, journal.receipt),
        Phase::Effected => EffectResult::Respond(
            Outcome::Success,
            success_receipt(&journal.binding, journal.post_generation),
        ),
        Phase::Reserved => {
            let current = state.current_cell();
            let current_identity = cell_identity(&current);
            if current_identity == journal.pre_identity {
                EffectResult::Respond(Outcome::Failure, failure_receipt(journal))
            } else if state.cells[..state.cell_records].iter().any(|cell| {
                cell.present
                    && cell.generation == journal.pre_generation.saturating_add(1)
                    && cell.binding == journal.binding
            }) {
                EffectResult::Respond(
                    Outcome::Success,
                    success_receipt(&journal.binding, journal.pre_generation.saturating_add(1)),
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

const RECORD_CHECKSUM: usize = RECORD_BYTES - 71;

fn load_state(block: &mut BlockDevice<'_>) -> PersistentState {
    let mut state = PersistentState::EMPTY;
    let mut header = [0_u8; 512];
    if block.read(0, &mut header).is_err() || validate_superblock(&header).is_err() {
        state.corrupt = true;
        return state;
    }
    let mut zero_seen = false;
    for record_index in 0..JOURNAL_RECORDS {
        let mut bytes = [0_u8; RECORD_BYTES];
        if block
            .read(JOURNAL_START_SECTOR + (record_index as u64) * 2, &mut bytes)
            .is_err()
        {
            state.corrupt = true;
            return state;
        }
        if bytes.iter().all(|byte| *byte == 0) {
            zero_seen = true;
            continue;
        }
        if zero_seen {
            state.corrupt = true;
            continue;
        }
        let Ok((slot, journal)) = decode_journal(&bytes, (record_index + 1) as u64) else {
            state.corrupt = true;
            continue;
        };
        if apply_journal(&mut state, slot, journal).is_err() {
            state.corrupt = true;
            continue;
        }
        state.journal_records += 1;
    }
    zero_seen = false;
    for record_index in 0..MAX_ATTEMPTS {
        let mut bytes = [0_u8; RECORD_BYTES];
        if block
            .read(CELL_START_SECTOR + (record_index as u64) * 2, &mut bytes)
            .is_err()
        {
            state.corrupt = true;
            return state;
        }
        if bytes.iter().all(|byte| *byte == 0) {
            zero_seen = true;
            continue;
        }
        if zero_seen {
            state.corrupt = true;
            continue;
        }
        let Ok(cell) = decode_cell(&bytes, (record_index + 1) as u64) else {
            state.corrupt = true;
            continue;
        };
        state.cells[record_index] = cell;
        state.cell_records += 1;
    }
    for journal in state
        .journals
        .iter()
        .filter(|journal| matches!(journal.phase, Phase::Effected | Phase::Committed))
    {
        if !state.cells[..state.cell_records].iter().any(|cell| {
            cell.generation == journal.post_generation && cell.binding == journal.binding
        }) {
            state.corrupt = true;
        }
    }
    for journal in state
        .journals
        .iter()
        .filter(|journal| journal.phase != Phase::Empty)
    {
        let prior = if journal.pre_generation == 0 {
            Cell::EMPTY
        } else if journal.pre_generation <= state.cell_records as u64 {
            state.cells[journal.pre_generation as usize - 1]
        } else {
            state.corrupt = true;
            continue;
        };
        if cell_identity(&prior) != journal.pre_identity {
            state.corrupt = true;
        }
    }
    for cell in &state.cells[..state.cell_records] {
        if !state.journals.iter().any(|journal| {
            journal.phase != Phase::Empty
                && journal.binding == cell.binding
                && journal.pre_generation.saturating_add(1) == cell.generation
        }) {
            state.corrupt = true;
        }
    }
    state
}

fn validate_superblock(header: &[u8; 512]) -> Result<(), ()> {
    if &header[..16] != b"DOCKET-S1B-RAW1!"
        || header[16..20] != 1_u32.to_be_bytes()
        || header[20..24] != 512_u32.to_be_bytes()
        || header[24..32] != (1024_u64 * 1024).to_be_bytes()
        || require_digest(&header[32..103]).is_err()
        || header[174..].iter().any(|byte| *byte != 0)
    {
        return Err(());
    }
    let checksum = transcript_digest(b"stage1b-device-superblock/v1", &[&header[..103]]);
    if header[103..174] != *checksum.as_slice() {
        return Err(());
    }
    Ok(())
}

fn append_journal(
    block: &mut BlockDevice<'_>,
    state: &mut PersistentState,
    slot: usize,
) -> Result<(), ()> {
    if state.journal_records == JOURNAL_RECORDS {
        return Err(());
    }
    let bytes = encode_journal(
        (state.journal_records + 1) as u64,
        slot,
        &state.journals[slot],
    )?;
    block.write(
        JOURNAL_START_SECTOR + (state.journal_records as u64) * 2,
        &bytes,
    )?;
    state.journal_records += 1;
    Ok(())
}

fn append_cell(
    block: &mut BlockDevice<'_>,
    state: &mut PersistentState,
    cell: Cell,
) -> Result<(), ()> {
    if state.cell_records == MAX_ATTEMPTS || cell.generation != (state.cell_records + 1) as u64 {
        return Err(());
    }
    let bytes = encode_cell(&cell)?;
    block.write(CELL_START_SECTOR + (state.cell_records as u64) * 2, &bytes)?;
    state.cells[state.cell_records] = cell;
    state.cell_records += 1;
    Ok(())
}

fn apply_journal(state: &mut PersistentState, slot: usize, incoming: Journal) -> Result<(), ()> {
    if slot >= MAX_ATTEMPTS {
        return Err(());
    }
    let current = state.journals[slot];
    match incoming.phase {
        Phase::Reserved
            if current.phase == Phase::Empty
                && incoming.post_generation == 0
                && incoming.receipt == Text::EMPTY =>
        {
            if state.journals.iter().any(|journal| {
                journal.phase != Phase::Empty && journal.binding.attempt == incoming.binding.attempt
            }) {
                return Err(());
            }
        }
        Phase::Effected
            if current.phase == Phase::Reserved
                && current.binding == incoming.binding
                && current.pre_generation == incoming.pre_generation
                && current.pre_identity == incoming.pre_identity
                && incoming.post_generation == incoming.pre_generation.saturating_add(1)
                && incoming.receipt == Text::EMPTY => {}
        Phase::Committed
            if current.phase == Phase::Effected
                && current.binding == incoming.binding
                && current.pre_generation == incoming.pre_generation
                && current.pre_identity == incoming.pre_identity
                && current.post_generation == incoming.post_generation
                && incoming.receipt
                    == success_receipt(&incoming.binding, incoming.post_generation) => {}
        _ => return Err(()),
    }
    state.journals[slot] = incoming;
    Ok(())
}

fn encode_journal(sequence: u64, slot: usize, journal: &Journal) -> Result<[u8; RECORD_BYTES], ()> {
    let mut bytes = [0_u8; RECORD_BYTES];
    bytes[..8].copy_from_slice(b"S1BJNL01");
    bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
    bytes[16] = slot as u8;
    bytes[17] = match journal.phase {
        Phase::Reserved => 1,
        Phase::Effected => 2,
        Phase::Committed => 3,
        Phase::Empty => return Err(()),
    };
    let mut offset = 18;
    put_binding(&mut bytes, &mut offset, &journal.binding)?;
    put_u64(&mut bytes, &mut offset, journal.pre_generation)?;
    put_text(&mut bytes, &mut offset, &journal.pre_identity)?;
    put_u64(&mut bytes, &mut offset, journal.post_generation)?;
    put_text(&mut bytes, &mut offset, &journal.receipt)?;
    let checksum = transcript_digest(b"stage1b-journal-record/v1", &[&bytes[..RECORD_CHECKSUM]]);
    bytes[RECORD_CHECKSUM..].copy_from_slice(checksum.as_slice());
    Ok(bytes)
}

fn decode_journal(bytes: &[u8; RECORD_BYTES], sequence: u64) -> Result<(usize, Journal), ()> {
    verify_record(bytes, b"stage1b-journal-record/v1")?;
    if &bytes[..8] != b"S1BJNL01" || bytes[8..16] != sequence.to_be_bytes() {
        return Err(());
    }
    let slot = usize::from(bytes[16]);
    let phase = match bytes[17] {
        1 => Phase::Reserved,
        2 => Phase::Effected,
        3 => Phase::Committed,
        _ => return Err(()),
    };
    let mut offset = 18;
    let binding = take_binding(bytes, &mut offset)?;
    let pre_generation = take_u64(bytes, &mut offset)?;
    let pre_identity = take_text(bytes, &mut offset)?;
    let post_generation = take_u64(bytes, &mut offset)?;
    let receipt = take_text(bytes, &mut offset)?;
    if bytes[offset..RECORD_CHECKSUM].iter().any(|byte| *byte != 0) {
        return Err(());
    }
    Ok((
        slot,
        Journal {
            phase,
            binding,
            pre_generation,
            pre_identity,
            post_generation,
            receipt,
        },
    ))
}

fn encode_cell(cell: &Cell) -> Result<[u8; RECORD_BYTES], ()> {
    let mut bytes = [0_u8; RECORD_BYTES];
    bytes[..8].copy_from_slice(b"S1BCEL01");
    bytes[8..16].copy_from_slice(&cell.generation.to_be_bytes());
    let mut offset = 16;
    put_binding(&mut bytes, &mut offset, &cell.binding)?;
    let checksum = transcript_digest(b"stage1b-cell-record/v1", &[&bytes[..RECORD_CHECKSUM]]);
    bytes[RECORD_CHECKSUM..].copy_from_slice(checksum.as_slice());
    Ok(bytes)
}

fn decode_cell(bytes: &[u8; RECORD_BYTES], generation: u64) -> Result<Cell, ()> {
    verify_record(bytes, b"stage1b-cell-record/v1")?;
    if &bytes[..8] != b"S1BCEL01" || bytes[8..16] != generation.to_be_bytes() {
        return Err(());
    }
    let mut offset = 16;
    let binding = take_binding(bytes, &mut offset)?;
    if bytes[offset..RECORD_CHECKSUM].iter().any(|byte| *byte != 0) {
        return Err(());
    }
    Ok(Cell {
        present: true,
        generation,
        binding,
    })
}

fn verify_record(bytes: &[u8; RECORD_BYTES], domain: &[u8]) -> Result<(), ()> {
    let checksum = transcript_digest(domain, &[&bytes[..RECORD_CHECKSUM]]);
    if bytes[RECORD_CHECKSUM..] != *checksum.as_slice() {
        return Err(());
    }
    Ok(())
}

fn put_binding(bytes: &mut [u8], offset: &mut usize, binding: &Binding) -> Result<(), ()> {
    binding.validate()?;
    for field in [
        &binding.attempt,
        &binding.marker,
        &binding.work_schema,
        &binding.work,
        &binding.subject,
        &binding.scope,
    ] {
        put_exact(bytes, offset, field.as_slice())?;
    }
    Ok(())
}

fn take_binding(bytes: &[u8], offset: &mut usize) -> Result<Binding, ()> {
    let binding = Binding {
        attempt: take_exact(bytes, offset, 71)?,
        marker: take_exact(bytes, offset, 71)?,
        work_schema: take_exact(bytes, offset, WORK_SCHEMA.len())?,
        work: take_exact(bytes, offset, 71)?,
        subject: take_exact(bytes, offset, 71)?,
        scope: take_exact(bytes, offset, 71)?,
    };
    binding.validate()?;
    Ok(binding)
}

fn put_exact(bytes: &mut [u8], offset: &mut usize, value: &[u8]) -> Result<(), ()> {
    let end = offset.checked_add(value.len()).ok_or(())?;
    bytes
        .get_mut(*offset..end)
        .ok_or(())?
        .copy_from_slice(value);
    *offset = end;
    Ok(())
}

fn take_exact(bytes: &[u8], offset: &mut usize, length: usize) -> Result<Text, ()> {
    let end = offset.checked_add(length).ok_or(())?;
    let value = Text::from_slice(bytes.get(*offset..end).ok_or(())?)?;
    *offset = end;
    Ok(value)
}

fn put_text(bytes: &mut [u8], offset: &mut usize, value: &Text) -> Result<(), ()> {
    let length = u8::try_from(value.len).map_err(|_| ())?;
    put_exact(bytes, offset, &[length])?;
    let end = offset.checked_add(MAX_TEXT).ok_or(())?;
    bytes
        .get_mut(*offset..end)
        .ok_or(())?
        .copy_from_slice(&value.bytes);
    *offset = end;
    Ok(())
}

fn take_text(bytes: &[u8], offset: &mut usize) -> Result<Text, ()> {
    let length = usize::from(*bytes.get(*offset).ok_or(())?);
    *offset += 1;
    if length > MAX_TEXT {
        return Err(());
    }
    let end = offset.checked_add(MAX_TEXT).ok_or(())?;
    let stored = bytes.get(*offset..end).ok_or(())?;
    if stored[length..].iter().any(|byte| *byte != 0) {
        return Err(());
    }
    let value = Text::from_slice(&stored[..length])?;
    *offset = end;
    Ok(value)
}

fn put_u64(bytes: &mut [u8], offset: &mut usize, value: u64) -> Result<(), ()> {
    put_exact(bytes, offset, &value.to_be_bytes())
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, ()> {
    let end = offset.checked_add(8).ok_or(())?;
    let value = u64::from_be_bytes(
        bytes
            .get(*offset..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    );
    *offset = end;
    Ok(value)
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
        b"vm-persistent-cell-evidence/v1",
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

const VIRTIO_MMIO: usize = 0xfeb0_0e00;
const QUEUE_SIZE: u16 = 8;
const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

#[repr(C, align(4096))]
struct QueueMemory {
    bytes: [u8; 8192],
}

impl QueueMemory {
    const fn new() -> Self {
        Self { bytes: [0; 8192] }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDescriptor {
    address: u64,
    length: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct BlockRequestHeader {
    request_type: u32,
    reserved: u32,
    sector: u64,
}

struct BlockDevice<'a> {
    queue: &'a mut QueueMemory,
    available: u16,
    used: u16,
}

impl<'a> BlockDevice<'a> {
    fn initialize(queue: &'a mut QueueMemory) -> Result<Self, ()> {
        if mmio_read(0x000) != 0x7472_6976 || mmio_read(0x004) != 1 || mmio_read(0x008) != 2 {
            return Err(());
        }
        mmio_write(0x070, 0);
        mmio_write(0x070, 1);
        mmio_write(0x070, 3);
        mmio_write(0x014, 0);
        let features = mmio_read(0x010);
        if features & VIRTIO_BLK_F_FLUSH == 0 {
            return Err(());
        }
        mmio_write(0x024, 0);
        mmio_write(0x020, VIRTIO_BLK_F_FLUSH);
        mmio_write(0x028, 4096);
        mmio_write(0x030, 0);
        if mmio_read(0x034) < u32::from(QUEUE_SIZE) {
            return Err(());
        }
        mmio_write(0x038, u32::from(QUEUE_SIZE));
        mmio_write(0x03c, 4096);
        let queue_address = queue.bytes.as_mut_ptr() as usize;
        if queue_address & 4095 != 0 || queue_address > u32::MAX as usize {
            return Err(());
        }
        mmio_write(0x040, (queue_address >> 12) as u32);
        let capacity = u64::from(mmio_read(0x100)) | (u64::from(mmio_read(0x104)) << 32);
        if capacity != 2048 {
            return Err(());
        }
        mmio_write(0x070, 7);
        Ok(Self {
            queue,
            available: 0,
            used: 0,
        })
    }

    fn read(&mut self, sector: u64, bytes: &mut [u8]) -> Result<(), ()> {
        self.transfer(0, sector, bytes.as_mut_ptr(), bytes.len(), true)
    }

    fn write(&mut self, sector: u64, bytes: &[u8]) -> Result<(), ()> {
        self.transfer(1, sector, bytes.as_ptr().cast_mut(), bytes.len(), false)?;
        self.transfer(4, 0, core::ptr::null_mut(), 0, false)
    }

    fn transfer(
        &mut self,
        request_type: u32,
        sector: u64,
        data: *mut u8,
        length: usize,
        device_writes: bool,
    ) -> Result<(), ()> {
        if request_type != 4
            && (length == 0
                || length > RECORD_BYTES
                || length % 512 != 0
                || sector.checked_add((length / 512) as u64).ok_or(())? > 2048)
        {
            return Err(());
        }
        let header = BlockRequestHeader {
            request_type,
            reserved: 0,
            sector,
        };
        let mut status = 0xff_u8;
        let (status_index, header_next) = if request_type == 4 {
            (1_u16, 1_u16)
        } else {
            (2_u16, 1_u16)
        };
        self.set_descriptor(
            0,
            (&header as *const BlockRequestHeader) as u64,
            core::mem::size_of::<BlockRequestHeader>() as u32,
            1,
            header_next,
        );
        if request_type != 4 {
            self.set_descriptor(
                1,
                data as u64,
                length as u32,
                1 | if device_writes { 2 } else { 0 },
                2,
            );
        }
        self.set_descriptor(
            usize::from(status_index),
            (&mut status as *mut u8) as u64,
            1,
            2,
            0,
        );
        let ring = usize::from(self.available % QUEUE_SIZE);
        self.write_u16(132 + ring * 2, 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        self.available = self.available.wrapping_add(1);
        self.write_u16(130, self.available);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        mmio_write(0x050, 0);
        while self.read_u16(4098) == self.used {
            core::hint::spin_loop();
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
        self.used = self.used.wrapping_add(1);
        if unsafe { core::ptr::read_volatile(&status) } != 0 {
            return Err(());
        }
        Ok(())
    }

    fn set_descriptor(&mut self, index: usize, address: u64, length: u32, flags: u16, next: u16) {
        let descriptor = VirtqDescriptor {
            address,
            length,
            flags,
            next,
        };
        unsafe {
            core::ptr::write_volatile(
                self.queue.bytes.as_mut_ptr().add(index * 16).cast(),
                descriptor,
            );
        }
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        unsafe {
            core::ptr::write_volatile(self.queue.bytes.as_mut_ptr().add(offset).cast(), value);
        }
    }

    fn read_u16(&self, offset: usize) -> u16 {
        unsafe { core::ptr::read_volatile(self.queue.bytes.as_ptr().add(offset).cast()) }
    }
}

fn mmio_read(offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((VIRTIO_MMIO + offset) as *const u32) }
}

fn mmio_write(offset: usize, value: u32) {
    unsafe { core::ptr::write_volatile((VIRTIO_MMIO + offset) as *mut u32, value) }
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
