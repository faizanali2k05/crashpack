//! Privacy-first local diagnostic bundles for Rust applications.
//!
//! `crashpack` captures only the data an application explicitly makes available:
//! panic information, a backtrace, build/runtime facts, bounded tracing events,
//! and attachments supplied by an [`AttachmentProvider`]. It never uploads a
//! report and never scans the environment, command line, home directory, or
//! network on its own.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::backtrace::Backtrace;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A provider of a user-approved diagnostic attachment.
pub trait AttachmentProvider: Send + Sync {
    /// A stable, human-readable file name without path separators.
    fn name(&self) -> &str;
    /// Produce the attachment bytes. Implementations should apply their own
    /// privacy filtering before returning data.
    fn collect(&self) -> Result<Vec<u8>, AttachmentError>;
}

/// Errors returned by an attachment provider.
#[derive(Debug, Error)]
pub enum AttachmentError {
    /// The provider could not collect its data.
    #[error("attachment collection failed: {0}")]
    Collection(String),
    /// The provider supplied an unsafe file name.
    #[error("attachment name contains a path separator: {0}")]
    UnsafeName(String),
}

/// A conservative policy for removing values that look like secrets or paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionPolicy {
    replacement: String,
    blocked_keys: Vec<String>,
    redact_paths: bool,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            replacement: "[REDACTED]".to_owned(),
            blocked_keys: [
                "password",
                "passwd",
                "secret",
                "token",
                "api_key",
                "apikey",
                "authorization",
                "credential",
                "private_key",
                "access_key",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            redact_paths: true,
        }
    }
}

impl RedactionPolicy {
    /// Construct the default conservative policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a case-insensitive metadata key that must be redacted.
    pub fn block_key(mut self, key: impl Into<String>) -> Self {
        self.blocked_keys.push(key.into().to_ascii_lowercase());
        self
    }

    /// Set the replacement marker used for redacted values.
    pub fn replacement(mut self, marker: impl Into<String>) -> Self {
        self.replacement = marker.into();
        self
    }

    /// Enable or disable conservative path redaction in free-form text.
    pub fn redact_paths(mut self, enabled: bool) -> Self {
        self.redact_paths = enabled;
        self
    }

    fn key_is_blocked(&self, key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        self.blocked_keys
            .iter()
            .any(|blocked| lower.contains(blocked))
    }

    /// Redact a metadata map without mutating the caller's values.
    pub fn metadata(&self, values: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        values
            .iter()
            .map(|(key, value)| {
                let value = if self.key_is_blocked(key) {
                    self.replacement.clone()
                } else {
                    self.text(value)
                };
                (key.clone(), value)
            })
            .collect()
    }

    /// Redact obvious secret assignments and, by default, absolute paths.
    pub fn text(&self, value: &str) -> String {
        let mut output = String::with_capacity(value.len());
        for token in value.split_whitespace() {
            let lower = token.to_ascii_lowercase();
            let secret_assignment = [
                "password=",
                "passwd=",
                "token=",
                "secret=",
                "api_key=",
                "apikey=",
            ]
            .iter()
            .any(|prefix| lower.starts_with(prefix));
            let path = self.redact_paths && (token.starts_with('/') || token.starts_with("\\\\"));
            if secret_assignment || path {
                output.push_str(&self.replacement);
            } else {
                output.push_str(token);
            }
            output.push(' ');
        }
        output.pop();
        output
    }
}

/// A bounded, thread-safe ring buffer for recent diagnostic events.
#[derive(Clone, Debug)]
pub struct TracingRingBuffer {
    inner: Arc<Mutex<VecDeque<String>>>,
    capacity: usize,
}

impl TracingRingBuffer {
    /// Create a ring buffer retaining at most `capacity` events.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity.max(1)))),
            capacity: capacity.max(1),
        }
    }

    /// Add an already-redacted event to the buffer.
    pub fn record(&self, event: impl Into<String>) {
        let Ok(mut events) = self.inner.lock() else {
            return;
        };
        if events.len() == self.capacity {
            events.pop_front();
        }
        events.push_back(event.into());
    }

    /// Return a stable snapshot in chronological order.
    pub fn snapshot(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|events| events.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Return the configured event capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Create an optional `tracing-subscriber` layer that records event names
    /// and fields after applying the supplied redaction policy.
    #[cfg(feature = "tracing")]
    pub fn layer(&self, policy: RedactionPolicy) -> TracingLayer {
        TracingLayer {
            buffer: self.clone(),
            policy,
        }
    }
}

#[cfg(feature = "tracing")]
/// A `tracing-subscriber` layer backed by a [`TracingRingBuffer`].
pub struct TracingLayer {
    buffer: TracingRingBuffer,
    policy: RedactionPolicy,
}

#[cfg(feature = "tracing")]
impl<S> tracing_subscriber::Layer<S> for TracingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Visitor<'a> {
            policy: &'a RedactionPolicy,
            fields: String,
        }
        impl tracing::field::Visit for Visitor<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                if self.policy.key_is_blocked(field.name()) {
                    self.fields.push_str(field.name());
                    self.fields.push_str("=[REDACTED] ");
                } else {
                    self.fields.push_str(field.name());
                    self.fields.push('=');
                    self.fields
                        .push_str(&self.policy.text(&format!("{value:?}")));
                    self.fields.push(' ');
                }
            }
        }
        let mut visitor = Visitor {
            policy: &self.policy,
            fields: String::new(),
        };
        event.record(&mut visitor);
        self.buffer.record(format!(
            "{} {}",
            event.metadata().name(),
            visitor.fields.trim()
        ));
    }
}

/// A user-supplied attachment included in a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Safe file name inside the bundle.
    pub name: String,
    /// Collected bytes.
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// Serializable crash report data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    /// Panic message or explicit diagnostic message.
    pub panic_message: String,
    /// Source location when the panic supplied one.
    pub source: Option<SourceLocation>,
    /// Captured Rust backtrace, if enabled.
    pub backtrace: Option<String>,
    /// Application version supplied by the caller.
    pub application_version: Option<String>,
    /// Compile-time target operating system.
    pub os: String,
    /// Compile-time target architecture.
    pub architecture: String,
    /// Target triple when Cargo supplied one at compile time.
    pub target: Option<String>,
    /// Explicit, redacted runtime metadata.
    pub metadata: BTreeMap<String, String>,
    /// Recent tracing events, if a buffer was configured.
    pub tracing_events: Vec<String>,
    /// User-supplied attachments.
    #[serde(skip)]
    pub attachments: Vec<Attachment>,
    /// Unix timestamp in seconds when capture started.
    pub captured_at_unix: u64,
}

/// Source location associated with a panic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceLocation {
    /// Source file path reported by Rust.
    pub file: String,
    /// One-based source line.
    pub line: u32,
    /// One-based source column.
    pub column: u32,
}

/// Errors returned while collecting or writing a crash report.
#[derive(Debug, Error)]
pub enum CrashpackError {
    /// Filesystem failure.
    #[error("filesystem error: {0}")]
    Io(#[from] io::Error),
    /// JSON serialization failure.
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// Attachment provider failure.
    #[error("attachment provider `{name}` failed: {source}")]
    Attachment {
        /// Provider name.
        name: String,
        /// Provider error.
        source: AttachmentError,
    },
    /// ZIP output was requested without enabling the `zip` feature.
    #[error("ZIP support requires the `zip` feature")]
    ZipFeatureDisabled,
    /// ZIP writer failure.
    #[cfg(feature = "zip")]
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Builder for privacy-controlled crash reports and panic hooks.
pub struct CrashpackBuilder {
    output_dir: PathBuf,
    application_version: Option<String>,
    policy: RedactionPolicy,
    include_backtrace: bool,
    metadata: BTreeMap<String, String>,
    tracing: Option<TracingRingBuffer>,
    attachments: Vec<Box<dyn AttachmentProvider>>,
}

impl fmt::Debug for CrashpackBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrashpackBuilder")
            .field("output_dir", &self.output_dir)
            .field("application_version", &self.application_version)
            .field("include_backtrace", &self.include_backtrace)
            .finish_non_exhaustive()
    }
}

impl CrashpackBuilder {
    /// Start a builder writing reports under `output_dir`.
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            application_version: None,
            policy: RedactionPolicy::default(),
            include_backtrace: true,
            metadata: BTreeMap::new(),
            tracing: None,
            attachments: Vec::new(),
        }
    }

    /// Set the application version shown in reports.
    pub fn application_version(mut self, version: impl Into<String>) -> Self {
        self.application_version = Some(version.into());
        self
    }

    /// Set the redaction policy.
    pub fn redaction_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Include or omit the Rust backtrace.
    pub fn include_backtrace(mut self, include: bool) -> Self {
        self.include_backtrace = include;
        self
    }

    /// Add explicit runtime metadata. No process environment is read.
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Attach a bounded tracing ring buffer.
    pub fn tracing_buffer(mut self, buffer: TracingRingBuffer) -> Self {
        self.tracing = Some(buffer);
        self
    }

    /// Add a user-approved attachment provider.
    pub fn attachment(mut self, provider: impl AttachmentProvider + 'static) -> Self {
        self.attachments.push(Box::new(provider));
        self
    }

    /// Build an immutable report collector.
    pub fn build(self) -> Crashpack {
        Crashpack {
            output_dir: self.output_dir,
            application_version: self.application_version,
            policy: self.policy,
            include_backtrace: self.include_backtrace,
            metadata: self.metadata,
            tracing: self.tracing,
            attachments: Arc::new(self.attachments),
        }
    }
}

/// A reusable collector that can capture explicit reports or install a panic hook.
#[derive(Clone)]
pub struct Crashpack {
    output_dir: PathBuf,
    application_version: Option<String>,
    policy: RedactionPolicy,
    include_backtrace: bool,
    metadata: BTreeMap<String, String>,
    tracing: Option<TracingRingBuffer>,
    attachments: Arc<Vec<Box<dyn AttachmentProvider>>>,
}

impl fmt::Debug for Crashpack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Crashpack")
            .field("output_dir", &self.output_dir)
            .field("application_version", &self.application_version)
            .finish_non_exhaustive()
    }
}

impl Crashpack {
    /// Capture an explicit diagnostic report with a message.
    pub fn capture(&self, message: impl AsRef<str>) -> Result<CrashReport, CrashpackError> {
        self.capture_inner(self.policy.text(message.as_ref()), None)
    }

    /// Capture and atomically create a JSON report file. Existing files are never overwritten.
    pub fn write_json(&self, message: impl AsRef<str>) -> Result<PathBuf, CrashpackError> {
        let report = self.capture(message)?;
        self.write_report_json(&report)
    }

    /// Capture and atomically create a ZIP report containing `report.json` and attachments.
    #[cfg(feature = "zip")]
    pub fn write_zip(&self, message: impl AsRef<str>) -> Result<PathBuf, CrashpackError> {
        let report = self.capture(message)?;
        self.write_report_zip(&report)
    }

    /// Return the configured output directory.
    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }

    /// Install a panic hook that writes a local ZIP (or JSON without the feature)
    /// and then invokes the previously installed hook. The hook never uploads data.
    pub fn install_panic_hook(&self) {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        if INSTALLED.set(()).is_err() {
            return;
        }
        let collector = self.clone();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            static IN_HOOK: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !IN_HOOK.swap(true, std::sync::atomic::Ordering::AcqRel) {
                let message = panic_message(info);
                if let Ok(report) = collector.capture_panic(info, message) {
                    #[cfg(feature = "zip")]
                    let _ = collector.write_report_zip(&report);
                    #[cfg(not(feature = "zip"))]
                    let _ = collector.write_report_json(&report);
                }
                IN_HOOK.store(false, std::sync::atomic::Ordering::Release);
            }
            previous(info);
        }));
    }

    fn capture_panic(
        &self,
        info: &std::panic::PanicHookInfo<'_>,
        message: String,
    ) -> Result<CrashReport, CrashpackError> {
        let source = info.location().map(|location| SourceLocation {
            file: self.policy.text(location.file()),
            line: location.line(),
            column: location.column(),
        });
        self.capture_inner(message, source)
    }

    fn capture_inner(
        &self,
        message: String,
        source: Option<SourceLocation>,
    ) -> Result<CrashReport, CrashpackError> {
        let attachments = self.collect_attachments()?;
        Ok(CrashReport {
            panic_message: message,
            source,
            backtrace: self
                .include_backtrace
                .then(|| Backtrace::force_capture().to_string()),
            application_version: self.application_version.clone(),
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            target: option_env!("TARGET").map(str::to_owned),
            metadata: self.policy.metadata(&self.metadata),
            tracing_events: self
                .tracing
                .as_ref()
                .map(TracingRingBuffer::snapshot)
                .unwrap_or_default(),
            attachments,
            captured_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    fn collect_attachments(&self) -> Result<Vec<Attachment>, CrashpackError> {
        self.attachments
            .iter()
            .map(|provider| {
                let name = provider.name().to_owned();
                if name.is_empty()
                    || name.contains('/')
                    || name.contains('\\')
                    || name == "."
                    || name == ".."
                {
                    return Err(CrashpackError::Attachment {
                        name: name.clone(),
                        source: AttachmentError::UnsafeName(name),
                    });
                }
                let data = provider
                    .collect()
                    .map_err(|source| CrashpackError::Attachment {
                        name: name.clone(),
                        source,
                    })?;
                Ok(Attachment { name, data })
            })
            .collect()
    }

    fn next_path(&self, extension: &str) -> Result<(File, PathBuf), CrashpackError> {
        fs::create_dir_all(&self.output_dir)?;
        let base = format!("crash-{}-{}", std::process::id(), unix_nanos());
        for suffix in 0..1000_u32 {
            let name = if suffix == 0 {
                format!("{base}.{extension}")
            } else {
                format!("{base}-{suffix}.{extension}")
            };
            let path = self.output_dir.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((file, path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not find a unique crash report path",
        )
        .into())
    }

    fn write_report_json(&self, report: &CrashReport) -> Result<PathBuf, CrashpackError> {
        let (mut file, path) = self.next_path("json")?;
        file.write_all(&serde_json::to_vec_pretty(report)?)?;
        file.flush()?;
        Ok(path)
    }

    #[cfg(feature = "zip")]
    fn write_report_zip(&self, report: &CrashReport) -> Result<PathBuf, CrashpackError> {
        let (file, path) = self.next_path("zip")?;
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        archive.start_file("report.json", options)?;
        archive.write_all(&serde_json::to_vec_pretty(report)?)?;
        for attachment in &report.attachments {
            archive.start_file(format!("attachments/{}", attachment.name), options)?;
            archive.write_all(&attachment.data)?;
        }
        archive.finish()?.sync_all()?;
        Ok(path)
    }
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    if let Some(message) = info.payload().downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    if let Some(message) = info.payload().downcast_ref::<String>() {
        return message.clone();
    }
    "panic payload was not a string".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct StaticAttachment;
    impl AttachmentProvider for StaticAttachment {
        fn name(&self) -> &str {
            "context.txt"
        }
        fn collect(&self) -> Result<Vec<u8>, AttachmentError> {
            Ok(b"approved context".to_vec())
        }
    }

    #[test]
    fn redaction_does_not_collect_environment() {
        let policy = RedactionPolicy::default();
        let mut metadata = BTreeMap::new();
        metadata.insert("api_token".into(), "secret-value".into());
        metadata.insert("safe".into(), "/home/user/private".into());
        let output = policy.metadata(&metadata);
        assert_eq!(output["api_token"], "[REDACTED]");
        assert_eq!(output["safe"], "[REDACTED]");
    }

    #[test]
    fn ring_buffer_is_bounded() {
        let buffer = TracingRingBuffer::new(2);
        buffer.record("one");
        buffer.record("two");
        buffer.record("three");
        assert_eq!(buffer.snapshot(), vec!["two", "three"]);
    }

    #[test]
    fn json_report_contains_attachment_metadata_without_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let collector = CrashpackBuilder::new(directory.path())
            .application_version("1.2.3")
            .attachment(StaticAttachment)
            .build();
        let path = collector.write_json("panic token=secret").unwrap();
        let json = fs::read_to_string(path).unwrap();
        assert!(json.contains("panic [REDACTED]"));
        assert!(json.contains("application_version"));
        assert!(!json.contains("approved context"));
    }

    #[test]
    fn reports_never_overwrite_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let collector = CrashpackBuilder::new(directory.path()).build();
        let first = collector.write_json("one").unwrap();
        let second = collector.write_json("two").unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }
}
