# Performance notes

Capture allocates the report strings and attachment bytes required for the output format. The tracing buffer is bounded, and its steady-state event storage is limited by the configured capacity. Backtrace capture is optional and can be disabled when a low-overhead explicit report is preferred. No benchmark claim is made until representative application workloads are measured.
