# crashpack

`crashpack` creates privacy-first, local diagnostic bundles for Rust applications. It captures a panic message, source location, optional Rust backtrace, explicit application metadata, bounded tracing events, and attachments that the application deliberately provides.

It is useful when an application needs a support artifact that a user can inspect before sharing. It does not upload anything, inspect arbitrary environment variables, read command-line arguments or home directories, or discover credentials and network data.

## Quick start

```toml
[dependencies]
crashpack = "0.1"
```

```rust,no_run
use crashpack::CrashpackBuilder;

fn main() {
    let crashpack = CrashpackBuilder::new("./crash-reports")
        .application_version(env!("CARGO_PKG_VERSION"))
        .metadata("screen", "settings")
        .build();
    crashpack.install_panic_hook();
}
```

## Features

- `zip` (default): writes `report.json` and approved attachments into a ZIP.
- `tracing`: enables the optional `TracingRingBuffer::layer` integration for `tracing-subscriber`.
- JSON output is always available with `Crashpack::write_json`.

Use `CrashpackBuilder::capture` when you need to review a report in memory before writing it. Attachments implement `AttachmentProvider`, so applications control exactly what enters a bundle.

## Privacy and security

The default `RedactionPolicy` removes common secret assignments and absolute paths from free-form text and blocks sensitive-looking metadata keys. Redaction is a defense in depth measure, not a proof that arbitrary user bytes are safe. Review user-provided attachments before sharing them. See [`docs/privacy.md`](docs/privacy.md) and [`docs/threat-model.md`](docs/threat-model.md).

## When not to use crashpack

Use a dedicated crash-reporting service when you need managed ingestion, alerting, or fleet-wide aggregation. Use a structured telemetry pipeline for continuous metrics. `crashpack` deliberately stops at local, user-controlled artifact creation.

## Support and compatibility

The MSRV is Rust 1.88. The library uses stable Rust and avoids unsafe code. Linux, macOS, and Windows are supported through Rust's portable standard library; platform-specific attachments remain the application's responsibility. The 0.1 API follows semantic versioning with additive changes preferred before 1.0.

## License

Licensed under either MIT or Apache-2.0 at the user's option.
