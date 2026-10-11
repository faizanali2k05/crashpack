# Privacy model

Crashpack starts from an allow-list. It records only panic data, compile-time OS and architecture, the application version and metadata explicitly passed to the builder, events explicitly recorded in `TracingRingBuffer`, and bytes returned by an attachment provider. It does not enumerate environment variables, command-line arguments, files, credentials, sockets, or network interfaces.

The default policy redacts common secret-looking metadata keys, secret assignments in text, and absolute paths. Applications should treat attachments as sensitive until reviewed and should ask users before sharing any generated file. No upload API exists in this crate.
