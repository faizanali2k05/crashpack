# Contributing

Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, and `cargo doc --all-features --no-deps` before opening a change. Keep privacy behavior explicit in tests and documentation. Do not add collection of environment, command-line, filesystem, network, or credential data without an opt-in API and a threat-model update.
