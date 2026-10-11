use std::process::Command;

use crashpack::CrashpackBuilder;

#[test]
fn panic_hook_writes_in_child_process() {
    if std::env::var_os("CRASHPACK_CHILD").is_some() {
        let directory = std::env::var("CRASHPACK_DIR").expect("child test directory");
        CrashpackBuilder::new(directory)
            .application_version("child-test")
            .include_backtrace(false)
            .build()
            .install_panic_hook();
        panic!("child panic token=private");
    }

    let directory = tempfile::tempdir().expect("temporary directory");
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("panic_hook_writes_in_child_process")
        .arg("--nocapture")
        .env("CRASHPACK_CHILD", "1")
        .env("CRASHPACK_DIR", directory.path())
        .output()
        .expect("spawn child test");
    assert!(
        !output.status.success(),
        "child panic unexpectedly succeeded"
    );
    let entries: Vec<_> = std::fs::read_dir(directory.path())
        .expect("report directory")
        .collect();
    assert_eq!(entries.len(), 1, "panic hook should create one report");
}
