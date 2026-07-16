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
fn limit_zero_means_unlimited() {
    // 8 probes should all appear in the plan; --limit only affects the
    // scan-time output, not --dry-run counting.
    let (code, out, _) = run({
        let mut c = bin();
        c.args([
            "--dry-run",
            "--limit",
            "0",
            "10.0.0.0/30",
            "--ports",
            "22,80",
        ]);
        c
    });
    assert_eq!(code, 0);
    assert!(out.contains("planned probes: 8"), "stdout: {out}");
}

#[test]
fn sort_unknown_exits_two() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args(["--dry-run", "--sort", "size", "10.0.0.1", "--ports", "22"]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("--sort"));
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
        c.args(["--dry-run", "--report", "all", "10.0.0.1", "--ports", "22"]);
        c
    });
    assert_eq!(code, 0);
}

#[test]
fn quiet_flag_conflicts_with_json() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args([
            "--dry-run",
            "--quiet",
            "--json",
            "10.0.0.1",
            "--ports",
            "22",
        ]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("cannot be used with"));
}

#[test]
fn help_and_version_succeed() {
    for flag in ["--help", "-h", "--version", "-V"] {
        let (code, out, _) = run({
            let mut c = bin();
            c.arg(flag);
            c
        });
        assert_eq!(code, 0, "{flag} should succeed");
        assert!(!out.is_empty(), "{flag} should print something");
    }
}

#[test]
fn json_dry_run_probes_matches_grid() {
    let (code, out, _) = run({
        let mut c = bin();
        c.args(["--dry-run", "--json", "10.0.0.0/28", "--ports", "22,80,443"]);
        c
    });
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    // 16 addresses × 3 ports.
    assert_eq!(v["probes"], serde_json::json!(48));
}

#[test]
fn wake_interval_ms_requires_wake() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args([
            "--dry-run",
            "--wake-interval-ms",
            "50",
            "10.0.0.1",
            "--ports",
            "22",
        ]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("--wake") || err.contains("requires"));
}

#[test]
fn wake_repeat_requires_wake() {
    // --wake-repeat without --wake is a clap error, exit 2.
    let (code, _, err) = run({
        let mut c = bin();
        c.args(["--dry-run", "--wake-repeat", "3", "10.0.0.1", "--ports", "22"]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("--wake") || err.contains("requires"));
}

#[test]
fn wake_repeat_zero_is_treated_as_one() {
    // clap accepts the flag; the underlying logic promotes 0 to 1 rather
    // than sending nothing at all.
    let (code, _, err) = run({
        let mut c = bin();
        c.args([
            "--wake",
            "aa:bb:cc:dd:ee:ff",
            "--wake-repeat",
            "0",
        ]);
        c
    });
    let is_wake_send_error = code == 2 && err.contains("wake AA:BB:CC:DD:EE:FF");
    assert!(
        code == 0 || is_wake_send_error,
        "unexpected outcome (code={code}, stderr={err})"
    );
}

#[test]
fn ports_preset_quick_parses() {
    let (code, out, _) = run({
        let mut c = bin();
        c.args(["--dry-run", "10.0.0.1", "--ports", "preset:quick"]);
        c
    });
    assert_eq!(code, 0);
    // QUICK_PORTS has 4 entries, one target.
    assert!(out.contains("planned probes: 4"), "stdout: {out}");
}

#[test]
fn ports_preset_unknown_exits_two() {
    let (code, _, err) = run({
        let mut c = bin();
        c.args(["--dry-run", "10.0.0.1", "--ports", "preset:nope"]);
        c
    });
    assert_eq!(code, 2);
    assert!(err.contains("preset"));
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
