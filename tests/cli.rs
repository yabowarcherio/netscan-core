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
fn wake_needs_no_target() {
    // --wake short-circuits target parsing; the wake itself either succeeds
    // or fails at the OS layer with a routing error (GitHub's macOS runners
    // refuse 255.255.255.255 broadcasts with ENETUNREACH/EHOSTUNREACH). The
    // invariant this test cares about is that clap didn't demand a positional
    // TARGET when --wake is set, which shows up as either exit 0 or an exit
    // 2 whose stderr mentions unreachability — never the clap 'required'
    // error.
    let (code, _, err) = run({
        let mut c = bin();
        c.args(["--wake", "aa:bb:cc:dd:ee:ff"]);
        c
    });
    // Success is exit 0; any exit 2 whose stderr mentions the wake target
    // (rather than clap's 'required argument') proves clap accepted the
    // absence of TARGET. Anything else is a real regression.
    let is_wake_send_error = code == 2 && err.contains("wake AA:BB:CC:DD:EE:FF");
    assert!(
        code == 0 || is_wake_send_error,
        "unexpected outcome (code={code}, stderr={err})"
    );
}

#[test]
fn wake_bad_mac_exits_two() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args(["--wake", "not-a-mac"]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("netscan"));
}

#[test]
fn report_unknown_exits_two() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args([
            "--dry-run",
            "--report",
            "everything",
            "10.0.0.1",
            "--ports",
            "22",
        ]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("--report"));
}

#[test]
fn report_all_recognized() {
    // The presence of --report all in --dry-run doesn't change the plan, but
    // it must not fail parsing either.
    let (code, _, _) = run({
        let mut c = bin();
        c.args([
            "--dry-run",
            "--report",
            "all",
            "10.0.0.1",
            "--ports",
            "22",
        ]);
        c
    });
    assert_eq!(code, 0);
}

#[test]
fn quiet_flag_conflicts_with_json() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args(["--dry-run", "--quiet", "--json", "10.0.0.1", "--ports", "22"]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("cannot be used with"));
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
