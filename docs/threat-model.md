# Threat model

The bundle is assumed to be written to a directory controlled by the application. A local attacker who can read that directory can read the bundle; use operating-system permissions and retention policies appropriate to the application. A malicious attachment provider can return arbitrary bytes, so applications must register only trusted providers.

Redaction reduces accidental disclosure but cannot identify every secret or infer the meaning of opaque user bytes. The panic hook attempts to fail safely: it uses unique create-new paths, catches ordinary collection errors, avoids re-entering its own capture path, and continues to the previously installed hook. It does not guarantee recovery from process aborts, out-of-memory conditions, or a hostile filesystem.
