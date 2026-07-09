# Contributing to netscan-core

Thanks for the interest. A few things to know before you open a PR.

## Scope

`netscan-core` is intentionally the *engine* — targets in, results out. If
you'd like to add a UI, a service-discovery layer, or platform-specific tricks
(raw sockets, ARP lookup), please open an issue first so we can decide whether
it belongs here or in a new companion crate.

## Design constraints

- **Safe Rust only.** `#![forbid(unsafe_code)]` is enforced.
- **No new heavy dependencies without discussion.** The sibling crates
  (`cidr-utils`, `portspec`, `oui-lookup`, `wol-rs`) plus `tokio` are the
  budget; the CLI adds `clap` + `serde_json`. Anything new should earn its
  weight.
- **Tests must not require the network.** Use ephemeral loopback listeners
  (see `tests/cli.rs` / `lib.rs`) and `127.0.0.1:1` as a "closed" port.

## Local checks

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --doc --all-features
```

CI runs the same checks plus MSRV, doc builds, and a cargo-deny advisories
pass. Please make them green before requesting review.

## Commit messages

Conventional prefixes (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`,
`ci:`, `bench:`) please. Keep the subject under 72 chars and put the "why" in
the body.
