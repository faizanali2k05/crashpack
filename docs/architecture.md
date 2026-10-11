# Architecture

`CrashpackBuilder` owns configuration and produces an immutable `Crashpack` collector. Capture builds a serializable `CrashReport`, applying `RedactionPolicy` to explicit text and metadata. `AttachmentProvider` values are invoked only during capture. JSON serialization is always available; the optional ZIP writer stores `report.json` and attachments under a fixed directory prefix.

`TracingRingBuffer` uses a bounded `VecDeque` behind a mutex. The optional tracing feature implements a subscriber `Layer` that formats event names and fields through the same redaction policy.
