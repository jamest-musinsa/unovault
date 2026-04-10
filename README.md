# unovault

> A beautiful, local-first, passkey-first personal vault for macOS. Your secrets on your disk, the way they should be.

**Status:** Week 1 — Rust scaffold in progress. Not yet runnable.

## What this is

unovault is a Mac desktop password manager and a Chrome extension, built around an open file format (`.unovault`) that you own. Your vault is an encrypted file on your disk. Sync is iCloud Drive in v1. No account, no server, no subscription. Your data stays yours.

The product thesis is: security tools should be beautiful enough that people want to open them, and open enough that nobody can lock you in.

Full design doc (private): `~/.gstack/projects/jamest-musinsa-unovault/james-main-design-20260410-190548.md` — problem statement, threat model, architecture, design spec v0, test plan, and the full dependency order for v1.

## Current layout

```
unovault/
├── Cargo.toml                         workspace manifest
├── crates/
│   └── unovault-core/                 vault engine: format, crypto, LWW event log
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── error.rs               5-category VaultError taxonomy
│           └── secret.rs              Secret<T> newtype — zeroize + redacted Debug
├── design/
│   └── spike/                         Week 0 taste validation mockups
│       ├── locked-home.html
│       ├── vault-list.html
│       └── item-detail.html
├── docs/                              format spec will go here (post-week-6)
├── CLAUDE.md                          project context for AI-assisted work
├── TODOS.md                           deferred work
└── README.md
```

## Build

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

The Tauri desktop app shell is not yet scaffolded — it lands in weeks 5–9 per the dependency order. Rust core comes first.

## Design references

- Things 3 (Cultured Code) — calmness, typography, whitespace
- Linear — keyboard-first, command bar, motion restraint
- Raycast — single-panel + command bar
- 1Password — the polish bar to beat
- Bitwarden — the OSS predecessor this product intentionally diverges from

## License

MIT (final choice landed after CEO review — see the design doc).

## Contributing

Not yet. The project is in its build phase and scope is tightly defined for v1. Once the public beta ships, the repo will have a proper `CONTRIBUTING.md` and an issue template. For now, watch the repo if you are curious.
