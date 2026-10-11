# Security notes

The crate forbids unsafe Rust and avoids process-wide data discovery. Report directories should be created with appropriate permissions. Treat generated files as potentially sensitive, review them before transmission, and avoid registering providers that include credentials or unrestricted user data.
