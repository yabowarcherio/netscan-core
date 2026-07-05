//! Black-box CLI tests. Only touch the network via 127.0.0.1 so they run on
//! any CI image without special permissions.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netscan"))
}

fn run(mut cmd: Command) -> (i32, String, String) {
    let out = cmd.output().expect("failed to spawn netscan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).expect("stdout not utf-8"),
        String::from_utf8(out.stderr).expect("stderr not utf-8"),
    )
}

#[test]
fn dry_run_text_reports_probe_plan() {
    let (code, out, _) = run({
        let mut c = bin();
        c.args(["--dry-run", "10.0.0.0/30", "--ports", "22,80"]);
        c
    });
    assert_eq!(code, 0);
    // 4 addresses × 2 ports = 8 probes.
    assert!(out.contains("planned probes: 8"), "stdout: {out}");
}

#[test]
fn dry_run_json_shape() {
    let (code, out, _) = run({
        let mut c = bin();
        c.args(["--dry-run", "--json", "10.0.0.1-10.0.0.4", "--ports", "22"]);
        c
    });
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert_eq!(v["probes"], serde_json::json!(4));
    assert!(v["timeout_ms"].is_number());
    assert!(v["concurrency"].is_number());
}

#[test]
fn bad_target_exits_two() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args(["--dry-run", "not-an-address"]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("netscan"));
}

#[test]
fn service_name_in_ports_parses() {
    let (code, out, _) = run({
        let mut c = bin();
        c.args(["--dry-run", "10.0.0.1", "--ports", "ssh,http,https"]);
        c
    });
    assert_eq!(code, 0);
    // 1 address × 3 ports.
    assert!(out.contains("planned probes: 3"), "stdout: {out}");
}
