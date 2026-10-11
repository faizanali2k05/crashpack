# Design decisions

- Local output is the only delivery mechanism. Uploading belongs to application code so consent, authentication, retention, and destination policy remain visible to users.
- Attachments are a trait instead of an automatic filesystem scanner. This makes the privacy boundary explicit and testable.
- Unique `create_new` paths prevent a panic from overwriting an earlier report, including when multiple processes use the same directory.
- A bounded ring buffer prevents unbounded memory growth from diagnostic events.
