//! Decode the scheduled tasks the system keeps in its registry.
//!
//! Each task is stored as three blobs: what it does, what starts it, and when
//! it last ran. The blobs are a serialisation of the scheduler's own objects,
//! so reading them recovers tasks whose files on disk have been removed.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::registry::RegistryHive;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{
    read_key, subkeys, values, RegistryKey, RegistryValue, ValueType,
};

pub struct ScheduledTasks;

/// Where the scheduler keeps its tasks.
const TASK_PATH: &[&str] = &[
    "Microsoft",
    "Windows NT",
    "CurrentVersion",
    "Schedule",
    "TaskCache",
];

/// The flags a task's settings are made of.
const JOB_FLAGS: &[(u64, &str)] = &[
    (0x2, "Run only if idle"),
    (0x4, "Restart on idle"),
    (0x8, "Stop on idle end"),
    (0x10, "Disallow start if on batteries"),
    (0x20, "Stop if going on batteries"),
    (0x40, "Start when available"),
    (0x80, "Run only if network available"),
    (0x100, "Allow start on demand"),
    (0x200, "Wake to run"),
    (0x400, "Execute parallel"),
    (0x800, "Execute stop existing"),
    (0x1000, "Execute queue"),
    (0x2000, "Execute ignore new"),
    (0x4000, "Logon type s4u"),
    (0x10000, "Logon type InteractiveToken"),
    (0x40000, "Logon type Password"),
    (0x80000, "Logon type InteractiveTokenOrPassword"),
    (0x400000, "Enabled"),
    (0x800000, "Hidden"),
    (0x1000000, "Runlevel highest available"),
    (0x2000000, "Task"),
    (0x4000000, "Version"),
    (0x8000000, "Token SID type none"),
    (0x10000000, "Token SID type unrestricted"),
    (0x20000000, "Interval"),
    (0x40000000, "Allow hard terminate"),
];

/// The days a weekly schedule may name.
const WEEKDAYS: &[(u64, &str)] = &[
    (0x1, "Sunday"),
    (0x2, "Monday"),
    (0x4, "Tuesday"),
    (0x8, "Wednesday"),
    (0x10, "Thursday"),
    (0x20, "Friday"),
    (0x40, "Saturday"),
];

/// The months a schedule may name.
const MONTHS: &[(u64, &str)] = &[
    (0x1, "January"),
    (0x2, "February"),
    (0x4, "March"),
    (0x8, "April"),
    (0x10, "May"),
    (0x20, "June"),
    (0x40, "July"),
    (0x80, "August"),
    (0x100, "September"),
    (0x200, "October"),
    (0x400, "November"),
    (0x800, "December"),
];

/// What starts a task.
#[derive(Clone, Copy, PartialEq)]
enum TriggerKind {
    WindowsNotificationFacility,
    Session,
    Registration,
    Logon,
    Event,
    Time,
    Idle,
    Boot,
}

impl TriggerKind {
    fn from_magic(magic: u64) -> Option<Self> {
        Some(match magic {
            0x6666 => TriggerKind::WindowsNotificationFacility,
            0x7777 => TriggerKind::Session,
            0x8888 => TriggerKind::Registration,
            0xAAAA => TriggerKind::Logon,
            0xCCCC => TriggerKind::Event,
            0xDDDD => TriggerKind::Time,
            0xEEEE => TriggerKind::Idle,
            0xFFFF => TriggerKind::Boot,
            _ => return None,
        })
    }

    fn name(&self) -> &'static str {
        match self {
            TriggerKind::WindowsNotificationFacility => "WindowsNotificationFacility",
            TriggerKind::Session => "Session",
            TriggerKind::Registration => "Registration",
            TriggerKind::Logon => "Logon",
            TriggerKind::Event => "Event",
            TriggerKind::Time => "Time",
            TriggerKind::Idle => "Idle",
            TriggerKind::Boot => "Boot",
        }
    }
}

/// What a task does when it starts.
///
/// The whole set is modelled even though this image contains only some of
/// them, since which kinds exist is part of what the format says.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq)]
enum ActionKind {
    Exe,
    ComHandler,
    Email,
    MessageBox,
}

impl ActionKind {
    fn name(&self) -> &'static str {
        match self {
            ActionKind::Exe => "Exe",
            ActionKind::ComHandler => "ComHandler",
            ActionKind::Email => "Email",
            ActionKind::MessageBox => "MessageBox",
        }
    }
}

/// How the times in a schedule are meant.
///
/// Only `Unknown` is ever produced, see `from_index`, but the modes the
/// scheduler defines are named here because that is what the field means.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq)]
enum TimeMode {
    Once,
    Daily,
    Weekly,
    DaysInMonths,
    DaysInWeeksInMonths,
    Unknown,
}

impl TimeMode {
    /// The mode a schedule records is a number, but the scheduler's own modes
    /// are named rather than numbered, so a recorded mode never matches one
    /// and a schedule is never described in words.
    fn from_index(_index: u64) -> Self {
        TimeMode::Unknown
    }
}

/// How a session trigger's state is named.
fn session_state(value: u64) -> &'static str {
    match value {
        1 => "ConsoleConnect",
        2 => "ConsoleDisconnect",
        3 => "RemoteConnect",
        4 => "RemoteDisconnect",
        5 => "SessionLock",
        6 => "SessionUnlock",
        _ => "Unknown",
    }
}

/// What a security identifier names.
fn sid_type(value: u64) -> &'static str {
    match value {
        1 => "User",
        2 => "Group",
        3 => "Domain",
        4 => "Alias",
        5 => "WellKnownGroup",
        6 => "DeletedAccount",
        7 => "Invalid",
        8 => "Unknown",
        9 => "Computer",
        10 => "Label",
        11 => "LogonSession",
        _ => "Unknown",
    }
}

/// A reader over one of the scheduler's blobs.
///
/// The blobs are written as the scheduler's own objects, with fields padded
/// out to eight-byte boundaries in places and not in others, so the reader
/// keeps both forms.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn seek(&mut self, forward: usize) {
        self.at = self.at.saturating_add(forward);
    }

    fn read(&mut self, length: usize) -> Option<&'a [u8]> {
        let taken = self.data.get(self.at..self.at + length)?;
        self.at += length;
        Some(taken)
    }

    fn unsigned(&mut self, size: usize, aligned: bool) -> Option<u64> {
        let taken = self.read(size)?;
        let mut buffer = [0u8; 8];
        buffer[..size].copy_from_slice(taken);
        if aligned {
            self.seek(8 - size);
        }
        Some(u64::from_le_bytes(buffer))
    }

    fn u1_aligned(&mut self) -> Option<u64> {
        self.unsigned(1, true)
    }

    fn u2(&mut self) -> Option<u64> {
        self.unsigned(2, false)
    }

    fn u4(&mut self) -> Option<u64> {
        self.unsigned(4, false)
    }

    fn u4_aligned(&mut self) -> Option<u64> {
        self.unsigned(4, true)
    }

    fn u8(&mut self) -> Option<u64> {
        self.unsigned(8, false)
    }

    fn boolean(&mut self) -> Option<bool> {
        self.read(1).map(|taken| taken[0] != 0)
    }

    /// A moment, preceded by a flag saying whether it was written in local
    /// time. A moment of zero or of every bit set is no moment at all.
    fn scheduler_time(&mut self) -> Option<u64> {
        self.u1_aligned()?;
        let filetime = self.u8()?;
        if filetime == 0 || filetime == u64::MAX {
            return None;
        }
        Some(filetime)
    }

    fn filetime(&mut self) -> Option<u64> {
        let filetime = self.u8()?;
        if filetime == 0 || filetime == u64::MAX {
            return None;
        }
        Some(filetime)
    }

    fn buffer(&mut self, aligned: bool) -> Option<Vec<u8>> {
        let count = if aligned { self.u4_aligned()? } else { self.u4()? } as usize;
        let taken = self.read(count)?.to_vec();
        if aligned {
            self.seek((8 - (count % 8)) % 8);
        }
        Some(taken)
    }

    /// A counted string. One of no length at all is no string.
    fn string(&mut self, aligned: bool) -> Option<String> {
        let size = if aligned { self.u4_aligned()? } else { self.u4()? } as usize;
        let taken = self.read(size)?;
        let text = decode_wide(taken);
        if aligned {
            self.seek((8 - (size % 8)) % 8);
        }
        if text.is_empty() {
            return None;
        }
        Some(text)
    }

    /// A string counted in characters rather than bytes, with room for its
    /// terminator.
    fn expandable_string(&mut self) -> Option<String> {
        let count = self.u4_aligned()? as usize;
        let bytes = count * 2 + 2;
        if count == 0 {
            return None;
        }
        let taken = self.read(bytes)?;
        let text = decode_wide(taken);
        self.seek((8 - (bytes % 8)) % 8);
        Some(text)
    }

    fn time_period(&mut self) -> Option<[u64; 7]> {
        let mut values = [0u64; 7];
        for value in values.iter_mut() {
            *value = self.u2()?;
        }
        Some(values)
    }

    fn position(&self) -> usize {
        self.at
    }
}

/// Decode wide text, dropping the terminator it carries.
fn decode_wide(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

/// What a task does when it runs.
struct Action {
    kind: ActionKind,
    action: String,
    arguments: Option<String>,
    working_directory: Option<String>,
}

/// Everything a task's action blob says.
struct ActionSet {
    /// Each action, or nothing where one could not be read at all.
    actions: Vec<Option<Action>>,
    context: Option<String>,
}

/// Decode the blob describing what a task does.
fn decode_actions(data: &[u8]) -> Option<ActionSet> {
    let mut reader = Reader::new(data);
    let version = reader.u2()?;
    // Only the later forms name the account the actions run as.
    let context = if version == 2 || version == 3 {
        reader.string(false)
    } else {
        None
    };

    let mut actions = Vec::new();
    loop {
        let Some(magic) = reader.u2() else { break };
        // Each action carries an identifier of its own, usually empty.
        reader.string(false);

        let action = match magic {
            0x8888 => {
                // An electronic mail action is read but never reported: the
                // reader gathers its parts and hands back nothing.
                decode_email(&mut reader);
                None
            }
            0x6666 => decode_executable(&mut reader, version),
            0x7777 => decode_com_handler(&mut reader),
            0x9999 => decode_message_box(&mut reader),
            _ => break,
        };
        actions.push(action);
    }
    Some(ActionSet { actions, context })
}

/// A program to run, with its arguments and where to run it.
fn decode_executable(reader: &mut Reader, version: u64) -> Option<Action> {
    let command = reader.string(false)?;
    let arguments = reader.string(false)?;
    let working_directory = reader.string(false);
    if version == 3 {
        reader.u2();
    }
    Some(Action {
        kind: ActionKind::Exe,
        action: command,
        arguments: Some(arguments),
        working_directory,
    })
}

/// A component to call, named by its identifier.
fn decode_com_handler(reader: &mut Reader) -> Option<Action> {
    let raw = reader.read(16)?.to_vec();
    let arguments = reader.string(false);
    Some(Action {
        kind: ActionKind::ComHandler,
        action: format_guid(&raw),
        arguments,
        working_directory: None,
    })
}

/// A message to show, which is reported as its caption and its text.
fn decode_message_box(reader: &mut Reader) -> Option<Action> {
    let caption = reader.string(false);
    let content = reader.string(false);
    Some(Action {
        kind: ActionKind::MessageBox,
        action: format!(
            "\"{}\": {}",
            caption.unwrap_or_else(|| "<Unknown>".to_string()),
            content.unwrap_or_else(|| "<Unknown>".to_string())
        ),
        arguments: None,
        working_directory: None,
    })
}

/// Read past an electronic mail action, which is recorded but not reported.
fn decode_email(reader: &mut Reader) {
    for _ in 0..8 {
        reader.string(false);
    }
    if let Some(attachments) = reader.u4() {
        for _ in 0..attachments {
            reader.string(false);
        }
    }
    if let Some(headers) = reader.u4() {
        for _ in 0..headers {
            reader.string(false);
            reader.string(false);
        }
    }
}

/// An identifier, written the way the scheduler writes one: each part in the
/// fewest digits that hold it.
fn format_guid(raw: &[u8]) -> String {
    if raw.len() != 16 {
        return String::new();
    }
    let first = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let second = u16::from_le_bytes(raw[4..6].try_into().unwrap());
    let third = u16::from_le_bytes(raw[6..8].try_into().unwrap());
    let fourth = u16::from_be_bytes(raw[8..10].try_into().unwrap());
    let mut last = [0u8; 8];
    last[2..].copy_from_slice(&raw[10..16]);
    let fifth = u64::from_be_bytes(last);
    format!("{{{first:x}-{second:x}-{third:x}-{fourth:x}-{fifth:x}}}")
}

/// What starts a task, and when.
struct Trigger {
    kind: TriggerKind,
    enabled: Option<bool>,
    description: Option<String>,
}

/// Everything a task's trigger blob says.
struct TriggerSet {
    principal_id: Option<String>,
    display_name: Option<String>,
    triggers: Vec<Option<Trigger>>,
}

/// Decode the blob describing what starts a task.
fn decode_triggers(data: &[u8]) -> Option<TriggerSet> {
    let mut reader = Reader::new(data);
    let version = reader.u1_aligned()?;
    reader.scheduler_time();
    reader.scheduler_time();

    // The settings shared by every trigger of this task come first.
    let flags = reader.u4_aligned()?;
    let _named: Vec<&str> = JOB_FLAGS
        .iter()
        .filter(|(flag, _)| flag & flags != 0)
        .map(|(_, name)| *name)
        .collect();
    reader.u4_aligned()?;

    let principal_id = if version >= 0x16 {
        reader.string(true)
    } else {
        None
    };
    let display_name = if version >= 0x17 {
        reader.string(true)
    } else {
        None
    };

    decode_user(&mut reader);
    decode_optional_settings(&mut reader);

    let mut triggers = Vec::new();
    loop {
        let Some(magic) = reader.u4_aligned() else {
            break;
        };
        let Some(kind) = TriggerKind::from_magic(magic) else {
            break;
        };
        let trigger = match kind {
            TriggerKind::Logon => decode_logon_trigger(&mut reader, version),
            TriggerKind::Session => decode_session_trigger(&mut reader, version),
            TriggerKind::WindowsNotificationFacility => {
                decode_notification_trigger(&mut reader, version)
            }
            TriggerKind::Event => decode_event_trigger(&mut reader, version),
            TriggerKind::Time => decode_time_trigger(&mut reader, version),
            // The remaining kinds carry nothing beyond what every trigger has.
            // Two of them are reported as though they were logon triggers.
            TriggerKind::Boot => decode_generic_trigger(&mut reader, version, TriggerKind::Boot),
            TriggerKind::Registration | TriggerKind::Idle => {
                decode_generic_trigger(&mut reader, version, TriggerKind::Logon)
            }
        };
        triggers.push(trigger);
    }

    Some(TriggerSet {
        principal_id,
        display_name,
        triggers,
    })
}

/// The parts every trigger begins with.
fn decode_generic_trigger(
    reader: &mut Reader,
    version: u64,
    kind: TriggerKind,
) -> Option<Trigger> {
    reader.scheduler_time();
    reader.scheduler_time();
    reader.u4();
    reader.u4();
    reader.u4();
    reader.u4();
    reader.u4();
    reader.boolean();
    reader.seek(3);
    let enabled = reader.u1_aligned().map(|value| value != 0);
    reader.seek(8);

    // Later versions name each trigger, and pad the name out to a block.
    if version >= 0x16 {
        let before = reader.position();
        reader.string(false);
        reader.seek((8 - (reader.position() - before) % 8) % 8);
    }

    Some(Trigger {
        kind,
        enabled,
        description: Some(format!("{} trigger", kind.name())),
    })
}

/// A trigger that fires when someone logs in.
fn decode_logon_trigger(reader: &mut Reader, version: u64) -> Option<Trigger> {
    let mut trigger = decode_generic_trigger(reader, version, TriggerKind::Logon)?;
    if let Some(user) = decode_user(reader) {
        if let Some(name) = user.username {
            trigger.description = Some(format!(
                "{name}: {} ({})",
                user.sid.unwrap_or_else(|| "None".to_string()),
                user.kind
                    .map(|kind| format!("SidType.{kind}"))
                    .unwrap_or_else(|| "None".to_string())
            ));
        }
    }
    Some(trigger)
}

/// A trigger that fires when a session changes.
fn decode_session_trigger(reader: &mut Reader, version: u64) -> Option<Trigger> {
    let mut trigger = decode_generic_trigger(reader, version, TriggerKind::Session)?;
    let state = reader.u4().map(session_state).unwrap_or("Unknown");
    reader.seek(4);

    trigger.description = match decode_user(reader).and_then(|user| user.username) {
        Some(name) => Some(format!("{state} for user {name}")),
        None => Some(state.to_string()),
    };
    Some(trigger)
}

/// A trigger that fires on a change the system publishes.
fn decode_notification_trigger(reader: &mut Reader, version: u64) -> Option<Trigger> {
    let mut trigger =
        decode_generic_trigger(reader, version, TriggerKind::WindowsNotificationFacility)?;
    let state: String = reader
        .read(8)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let length = reader.u4_aligned()? as usize;
    reader.read(length);
    trigger.description = Some(format!("WNF state {state}"));
    Some(trigger)
}

/// A trigger that fires on a logged event.
fn decode_event_trigger(reader: &mut Reader, version: u64) -> Option<Trigger> {
    let mut trigger = decode_generic_trigger(reader, version, TriggerKind::Event)?;
    let subscription = reader.expandable_string();
    reader.seek(8);
    reader.expandable_string();
    let Some(count) = reader.u4_aligned() else {
        return Some(trigger);
    };

    let mut queries = Vec::new();
    for _ in 0..count {
        let name = reader.expandable_string();
        let value = reader.expandable_string();
        if let (Some(name), Some(value)) = (name, value) {
            queries.push(format!("('{name}', '{value}')"));
        }
    }
    let described = trigger
        .description
        .unwrap_or_else(|| "Event Trigger".to_string());
    trigger.description = Some(format!(
        "{described}: Subscription: {}, Queries: [{}]",
        subscription.unwrap_or_else(|| "None".to_string()),
        queries.join(", ")
    ));
    Some(trigger)
}

/// A trigger that fires at a time, or on a schedule of them.
fn decode_time_trigger(reader: &mut Reader, version: u64) -> Option<Trigger> {
    let schedule = decode_schedule(reader)?;
    if version >= 0x16 {
        let before = reader.position();
        reader.string(false);
        reader.seek((8 - (reader.position() - before) % 8) % 8);
    }
    Some(Trigger {
        kind: TriggerKind::Time,
        enabled: schedule.enabled,
        description: schedule.description,
    })
}

/// When a task is meant to run.
struct Schedule {
    enabled: Option<bool>,
    description: Option<String>,
}

/// Decode a schedule, and say in words what it comes to.
fn decode_schedule(reader: &mut Reader) -> Option<Schedule> {
    let start = reader.scheduler_time();
    reader.scheduler_time();
    reader.scheduler_time();
    reader.u4();
    reader.u4();
    reader.u4();
    let mode = reader.u4().map(TimeMode::from_index);

    let first = reader.u2();
    let second = reader.u2();
    let third = reader.u2();

    reader.seek(2);
    reader.boolean();
    let enabled = reader.boolean();
    reader.seek(6);
    reader.u4();
    reader.seek(4);

    let starting = match start {
        Some(time) => python_isoformat(time),
        None => "<UNKNOWN>".to_string(),
    };
    let description = match mode {
        Some(TimeMode::Once) => Some(format!("Run one time starting at {starting}")),
        Some(TimeMode::Daily) => first.map(|days| {
            format!("Run at {starting} and repeat every {days} days")
        }),
        Some(TimeMode::Weekly) => second.map(|mask| {
            let days: Vec<&str> = WEEKDAYS
                .iter()
                .filter(|(flag, _)| flag & mask != 0)
                .map(|(_, name)| *name)
                .collect();
            format!(
                "Run on {} every {} weeks starting at {starting}",
                days.join(", "),
                first.map(|value| value.to_string()).unwrap_or_else(|| "None".to_string())
            )
        }),
        Some(TimeMode::DaysInMonths) => match (first, second, third) {
            (Some(low), Some(high), Some(months_mask)) => {
                let months: Vec<&str> = MONTHS
                    .iter()
                    .filter(|(flag, _)| flag & months_mask != 0)
                    .map(|(_, name)| *name)
                    .collect();
                let bitmap = (high << 16) + low;
                let days: Vec<String> = (0..31)
                    .filter(|bit| (1u64 << bit) & bitmap != 0)
                    .map(|bit| (bit + 1).to_string())
                    .collect();
                Some(format!(
                    "Run in months {} on days {} starting at {starting}",
                    months.join(", "),
                    days.join(", ")
                ))
            }
            _ => None,
        },
        Some(TimeMode::DaysInWeeksInMonths) => match (first, second, third) {
            (Some(days_mask), Some(weeks_mask), Some(months_mask)) => {
                let months: Vec<&str> = MONTHS
                    .iter()
                    .filter(|(flag, _)| flag & months_mask != 0)
                    .map(|(_, name)| *name)
                    .collect();
                // The weeks are numbered by a shift of the index rather than a
                // bit of it, which is how upstream reads them.
                let weeks: Vec<String> = (0..5u64)
                    .filter(|index| (index << 1) & weeks_mask != 0)
                    .map(|index| (index + 1).to_string())
                    .collect();
                let days: Vec<&str> = WEEKDAYS
                    .iter()
                    .filter(|(flag, _)| flag & days_mask != 0)
                    .map(|(_, name)| *name)
                    .collect();
                Some(format!(
                    "Run in months {} in weeks {} on days {} starting at {starting}",
                    months.join(", "),
                    weeks.join(", "),
                    days.join(", ")
                ))
            }
            _ => None,
        },
        _ => None,
    };

    Some(Schedule {
        enabled,
        description,
    })
}

/// Who a task runs as.
struct UserInfo {
    kind: Option<&'static str>,
    sid: Option<String>,
    username: Option<String>,
}

/// Decode the account a task or trigger names.
fn decode_user(reader: &mut Reader) -> Option<UserInfo> {
    let skip_user = reader.u1_aligned()? != 0;
    let skip_sid = if !skip_user {
        reader.u1_aligned()? != 0
    } else {
        false
    };

    let mut kind = None;
    let mut sid = None;
    if !skip_user && !skip_sid {
        kind = Some(sid_type(reader.u4_aligned()?));
        let raw = reader.buffer(true)?;
        sid = decode_sid(&raw);
    }

    let username = if !skip_user {
        reader.string(true)
    } else {
        None
    };
    Some(UserInfo {
        kind,
        sid,
        username,
    })
}

/// A security identifier, written the way one is written.
fn decode_sid(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let revision = data[0] as u64;
    let count = data[1] as usize;
    let mut authority = [0u8; 8];
    authority[2..].copy_from_slice(&data[2..8]);
    let authority = u64::from_be_bytes(authority);

    let mut parts = vec![revision.to_string(), authority.to_string()];
    for index in 0..count {
        let at = 8 + index * 4;
        let value = data.get(at..at + 4)?;
        parts.push(u32::from_le_bytes(value.try_into().ok()?).to_string());
    }
    Some(format!("S-{}", parts.join("-")))
}

/// Read past the settings a task may carry beyond the shared ones.
fn decode_optional_settings(reader: &mut Reader) -> Option<()> {
    const WITH_PRIVILEGES: u64 = 0x38;
    const WITH_TIME_PERIODS: u64 = 0x58;

    let length = reader.u4_aligned()?;
    if length == 0 {
        return None;
    }
    for _ in 0..7 {
        reader.u4()?;
    }
    reader.read(16)?;
    reader.seek(4);

    if length == WITH_PRIVILEGES || length == WITH_TIME_PERIODS {
        reader.u8()?;
    }
    if length == WITH_TIME_PERIODS {
        reader.time_period()?;
        reader.time_period()?;
        reader.boolean()?;
        reader.seek(3);
    }
    Some(())
}

/// When a task last ran, as the scheduler recorded it.
struct DynamicInfo {
    /// The moment reported as the task's creation, which is the moment the
    /// scheduler wrote as its last run.
    creation_time: Option<u64>,
    last_run_time: Option<u64>,
    last_successful_run_time: Option<u64>,
}

/// Decode the blob describing when a task last ran.
fn decode_dynamic_info(data: &[u8]) -> Option<DynamicInfo> {
    let mut reader = Reader::new(data);
    if reader.u4()? != 3 {
        return None;
    }
    let created = reader.filetime();
    let last_run = reader.filetime();
    reader.seek(4);
    reader.u4();
    let last_success = reader.filetime();

    // The two moments are reported the other way about, as upstream reports
    // them.
    Some(DynamicInfo {
        creation_time: last_run,
        last_run_time: created,
        last_successful_run_time: last_success,
    })
}

/// A moment, written the way the interpreter writes one.
fn python_isoformat(filetime: u64) -> String {
    match wintime_value(filetime) {
        Value::DateTime(time) => time.format("%Y-%m-%dT%H:%M:%S%.f").to_string(),
        _ => "<UNKNOWN>".to_string(),
    }
}

impl Plugin for ScheduledTasks {
    fn name(&self) -> &'static str {
        "windows.registry.scheduled_tasks.ScheduledTasks"
    }

    fn description(&self) -> &'static str {
        "Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Task Name"),
            Column::string("Principal ID"),
            Column::string("Display Name"),
            Column::bool("Enabled"),
            Column::datetime("Creation Time"),
            Column::datetime("Last Run Time"),
            Column::datetime("Last Successful Run Time"),
            Column::string("Trigger Type"),
            Column::string("Trigger Description"),
            Column::string("Action Type"),
            Column::string("Action"),
            Column::string("Action Arguments"),
            Column::string("Action Context"),
            Column::string("Working Directory"),
            Column::string("Key Name"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};
        #[allow(unused_imports)]
        use crate::framework::plugins::timeline_helpers::{is_time, number, text};

        let mut timeline = Timeline::new();
        for row in self.run(context, config).ok()?.rows() {
            let values = &row.values;
            if is_time(&values[5]) {
                timeline.push(
                    format!(
                        "ScheduledTasks: task action {} with trigger {} ran",
                        text(&values[10]),
                        text(&values[8])
                    ),
                    TimeKind::Accessed,
                    values[5].clone(),
                );
            }
            if is_time(&values[6]) {
                timeline.push(
                    format!(
                        "ScheduledTasks: task action {} with trigger {} ran successfully",
                        text(&values[10]),
                        text(&values[8])
                    ),
                    TimeKind::Accessed,
                    values[6].clone(),
                );
            }
            if is_time(&values[4]) {
                // Only a trigger with nothing in it at all is called unknown.
                // One that could not be read still says so.
                let trigger = match text(&values[8]) {
                    described if described.is_empty() => "<UNKNOWN>".to_string(),
                    described => described,
                };
                timeline.push(
                    format!(
                        "ScheduledTasks: Creation Time for task {} with trigger {trigger}",
                        text(&values[14])
                    ),
                    TimeKind::Created,
                    values[4].clone(),
                );
            }
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();
        let mut grid = TreeGrid::new(self.columns());

        // The tasks live in the machine's software hive.
        let mut hive = None;
        for hive_object in super::list_hives(&context, &kernel)? {
            let Ok(candidate) = super::open_hive(&context, &kernel, hive_object) else {
                continue;
            };
            if candidate
                .hive_name()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("software")
            {
                hive = Some(candidate);
                break;
            }
        }
        let Some(hive) = hive else {
            return Ok(grid);
        };

        let Ok(root) = read_key(&context, &hive, &table, hive.root_cell_offset(), String::new())
        else {
            return Ok(grid);
        };
        let Some(cache) = descend(&context, &hive, &table, &root, TASK_PATH) else {
            return Ok(grid);
        };
        let Some(tasks) = descend(&context, &hive, &table, &cache, &["Tasks"]) else {
            return Ok(grid);
        };

        // The tree names each task. The tasks themselves are keyed by
        // identifier.
        let mut names: HashMap<String, String> = HashMap::new();
        if let Some(tree) = descend(&context, &hive, &table, &cache, &["Tree"]) {
            collect_names(&context, &hive, &table, &tree, &mut names);
        }

        for key in subkeys(&context, &hive, &table, &tasks).unwrap_or_default() {
            for row in task_rows(&context, &hive, &table, &key, &names) {
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// The rows one task produces: one for every pairing of what it does with what
/// starts it.
fn task_rows(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    key: &RegistryKey,
    names: &HashMap<String, String>,
) -> Vec<Vec<Value>> {
    let mut blobs: HashMap<String, RegistryValue> = HashMap::new();
    for value in values(context, hive, table, key).unwrap_or_default() {
        let Ok(name) = value.name() else { continue };
        if ["Actions", "Triggers", "DynamicInfo"].contains(&name.as_str()) {
            blobs.insert(name, value);
        }
    }

    let key_name = key.name().ok();
    let task_name = key_name
        .as_ref()
        .and_then(|name| names.get(name))
        .cloned();

    let actions = blobs
        .get("Actions")
        .and_then(|value| binary(value, hive))
        .and_then(|data| decode_actions(&data));
    let triggers = blobs
        .get("Triggers")
        .and_then(|value| binary(value, hive))
        .and_then(|data| decode_triggers(&data));
    let dynamic = blobs
        .get("DynamicInfo")
        .and_then(|value| binary(value, hive))
        .and_then(|data| decode_dynamic_info(&data));

    let (principal_id, display_name) = match &triggers {
        Some(set) => (set.principal_id.clone(), set.display_name.clone()),
        None => (None, None),
    };

    let time = |value: Option<u64>| -> Value {
        match value {
            Some(filetime) => wintime_value(filetime),
            None => Value::not_available(),
        }
    };
    let created = time(dynamic.as_ref().and_then(|info| info.creation_time));
    let last_run = time(dynamic.as_ref().and_then(|info| info.last_run_time));
    let last_success = time(dynamic.as_ref().and_then(|info| info.last_successful_run_time));

    // A task with no actions, or none that could be read, still reports what
    // starts it, and the other way about.
    let action_count = actions
        .as_ref()
        .map(|set| set.actions.len().max(1))
        .unwrap_or(1);
    let trigger_count = triggers
        .as_ref()
        .map(|set| set.triggers.len().max(1))
        .unwrap_or(1);

    let text = |value: Option<String>| -> Value {
        match value {
            Some(value) => Value::string(value),
            None => Value::not_available(),
        }
    };

    let mut rows = Vec::new();
    for action_index in 0..action_count {
        for trigger_index in 0..trigger_count {
            let action = actions
                .as_ref()
                .and_then(|set| set.actions.get(action_index))
                .and_then(|action| action.as_ref());
            let trigger = triggers
                .as_ref()
                .and_then(|set| set.triggers.get(trigger_index))
                .and_then(|trigger| trigger.as_ref());

            let (arguments, working_directory) = match action {
                Some(action) => {
                    let arguments = match action.kind {
                        ActionKind::Exe | ActionKind::ComHandler => {
                            text(action.arguments.clone())
                        }
                        // The other kinds carry nothing of the sort.
                        _ => Value::not_applicable(),
                    };
                    let directory = match action.kind {
                        ActionKind::Exe => text(action.working_directory.clone()),
                        _ => Value::not_applicable(),
                    };
                    (arguments, directory)
                }
                None => (Value::not_available(), Value::not_available()),
            };

            rows.push(vec![
                text(task_name.clone()),
                text(principal_id.clone()),
                text(display_name.clone()),
                match trigger.and_then(|trigger| trigger.enabled) {
                    Some(enabled) => Value::Bool(enabled),
                    None => Value::not_available(),
                },
                created.clone(),
                last_run.clone(),
                last_success.clone(),
                match trigger {
                    Some(trigger) => Value::string(trigger.kind.name()),
                    None => Value::not_available(),
                },
                match trigger.and_then(|trigger| trigger.description.clone()) {
                    Some(description) => Value::string(description),
                    None => Value::not_available(),
                },
                match action {
                    Some(action) => Value::string(action.kind.name()),
                    None => Value::not_available(),
                },
                match action {
                    Some(action) => Value::string(action.action.clone()),
                    None => Value::not_available(),
                },
                arguments,
                match actions.as_ref().and_then(|set| set.context.clone()) {
                    Some(context) => Value::string(context),
                    None => Value::not_available(),
                },
                working_directory,
                text(key_name.clone()),
            ]);
        }
    }
    rows
}

/// A value's raw bytes, where it holds bytes at all.
fn binary(value: &RegistryValue, hive: &RegistryHive) -> Option<Vec<u8>> {
    if matches!(
        value.value_type(),
        ValueType::Dword | ValueType::DwordBigEndian | ValueType::Qword
    ) {
        return None;
    }
    value.data(hive).ok()
}

/// Walk the tree of task names, keyed by the identifier each names.
fn collect_names(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    key: &RegistryKey,
    names: &mut HashMap<String, String>,
) {
    if let Some(identifier) = values(context, hive, table, key)
        .unwrap_or_default()
        .into_iter()
        .find(|value| value.name().map(|name| name == "Id").unwrap_or(false))
    {
        if identifier.value_type() == ValueType::String {
            if let (Ok(data), Ok(name)) = (identifier.data(hive), key.name()) {
                names.insert(decode_wide(&data), name);
            }
        }
    }

    for child in subkeys(context, hive, table, key).unwrap_or_default() {
        collect_names(context, hive, table, &child, names);
    }
}

/// Follow a path of subkey names, which the registry matches without regard to
/// case.
fn descend(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    start: &RegistryKey,
    path: &[&str],
) -> Option<RegistryKey> {
    let mut current = start.clone();
    for component in path {
        let children = subkeys(context, hive, table, &current).ok()?;
        current = children.into_iter().find(|child| {
            child
                .name()
                .map(|name| name.to_lowercase() == component.to_lowercase())
                .unwrap_or(false)
        })?;
    }
    Some(current)
}
