use crashpack::CrashpackBuilder;

fn main() {
    let collector = CrashpackBuilder::new("target/crash-reports")
        .application_version("1.0.0")
        .metadata("component", "example")
        .build();
    let path = collector
        .write_json("explicit diagnostic message")
        .expect("example output should be writable");
    println!("wrote {}", path.display());
}
