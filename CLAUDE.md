# CLAUDE.md — unovault

This file gives Claude (and other AI coding assistants) the context it needs to work on unovault without re-reading every design doc from scratch.

## What you're working on

unovault is a local-first, passkey-first macOS password manager plus a Chrome extension, built around an open vault file format (`.unovault`). The product thesis is "security tools should be beautiful enough that people want to open them, and open enough that nobody can lock you in." Target user is a tech-savvy non-developer — designers, PMs, writers, marketers — who left 1Password over subscription prices and needs things to "just work." Budget: ~6 months part-time solo.

Full design doc: `~/.gstack/projects/jamest-musinsa-unovault/james-main-design-20260410-190548.md` (outside the repo). CEO plan: `~/.gstack/projects/jamest-musinsa-unovault/ceo-plans/2026-04-10-unovault-v1.md`. These are the source of truth — read them before any non-trivial change. The design doc went through 5 review passes (2× office-hours, eng, design, CEO) and has a Reviewer Concerns section at the bottom listing the remaining spec holes.

## Status

**Week 1.** Cargo workspace set up. `unovault-core` has the error taxonomy and `Secret<T>` wrapper. Everything else is still to build. No Tauri app shell yet — that lands in weeks 5–9.

## Architectural rules (non-negotiable)

1. **Never panic on valid input.** `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::todo`, `clippy::unimplemented` are deny at the workspace root. Exceptions need an explicit `#[allow(...)]` with a one-line comment explaining why.
2. **Every fallible function returns `Result<T, VaultError>`.** The 5-category error taxonomy in `crates/unovault-core/src/error.rs` is the only supported error type. No `anyhow`, no string errors, no per-module bespoke enums unless they `#[from]` into `VaultError`.
3. **Every secret is `Secret<T>`.** Master passwords, derived keys, decrypted credential values, recovery phrases, and passkey private material all go through `crates/unovault-core/src/secret.rs`. Bare `String` or `Vec<u8>` for sensitive material is a review-blocker.
4. **No plaintext credential material in Tauri IPC return types.** When the app shell lands, a `#[unovault::safe_command]` proc-macro enforces this at compile time. Until then, keep the invariant in your head: the UI only ever sees item metadata.
5. **Vault file is a directory, not a file.** The `.unovault` bundle contains `manifest.json` (immutable, HMAC-protected), `chunks/` (append-only encrypted events), and `snapshots/` (compacted state). See the design doc's "Vault File Format" section for the byte layout.
6. **Merge semantics are per-item LWW**, not a full CRDT. automerge was considered and rejected in the eng review for being overkill on a single-user vault.
7. **No colored font stacks, no Inter default, no purple.** The design system lives in `design/` and the spikes are the reference. Terracotta accent is `#B8532C`.

## Current crate layout

```
crates/
└── unovault-core/     vault engine — format, crypto, LWW events
    └── src/
        ├── lib.rs     module root + architectural rules as doc comments
        ├── error.rs   VaultError + 5 sub-enums (UserActionable, NetworkTransient,
        │              HardwareIssue, BugInUnovault, PlatformPolicy)
        └── secret.rs  Secret<T> newtype — zeroize on drop, redacted Debug,
                       no Display, no Clone
```

Future crates (not yet scaffolded):

- `unovault-import` — 1Password 1pux, Bitwarden JSON, KeePass XML parsers
- `unovault-passkey` — CTAP2 authenticator via `passkey-rs` (Mac-only, Cargo feature)
- `unovault-sync` — async `SyncBackend` trait + iCloud impl
- `unovault-biometric` — thin Rust wrapper over Swift `LocalAuthentication`

## Build + test commands

```sh
# Full check — run this before any commit
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

# Quick test during development
cargo test -p unovault-core

# Format the whole workspace
cargo fmt
```

No Tauri build commands yet — they land in weeks 5–9 when the app shell is scaffolded.

## Design references

The Week 0 taste validation spikes live in `design/spike/`:

- `locked-home.html` — the unlock screen (Touch ID + master password)
- `vault-list.html` — the command bar + single panel post-unlock state
- `item-detail.html` — the slide-up sheet for a single credential

These are the canonical visual reference for the whole product. When implementing the Svelte UI in weeks 7–9, match these pixel-for-pixel. The design tokens (colors, typography, spacing, radius, shadow, motion) are duplicated at the top of each HTML file and will be consolidated into a Svelte design system in weeks 10–13.

Aesthetic references: Things 3, Linear, Raycast, 1Password (bar to beat), Bitwarden (predecessor to diverge from). Do not introduce SaaS-template patterns — purple gradients, 3-column feature grids, icons-in-colored-circles, generic hero copy. The design doc has an explicit anti-slop list in the "Delight Touches" and "What Makes This Cool" sections.

## Testing expectations

See the test plan artifact at `~/.gstack/projects/jamest-musinsa-unovault/james-main-eng-review-test-plan-20260410-193949.md` for the full coverage target.

Quick summary of what "done" looks like for each module:

- Unit tests for every public function in `unovault-core`
- Property tests (`proptest`) for crypto round-trip invariants: encrypt/decrypt identity, no plaintext in ciphertext bytes, tampered ciphertext fails MAC
- `miri` run on the `secret` module to validate zeroize-on-drop semantics
- Integration tests using a `FileSystemBackend` trait + chaos harness for sync
- E2E tests via `tauri-driver` + Playwright once the app shell lands

Target: 80% line coverage on `unovault-core` enforced by `cargo-llvm-cov` in CI.

## What NOT to do

- Do not add telemetry, analytics, or crash-reporting SaaS. The product is privacy-first by design. The observability section in the design doc covers what's allowed (local structured logs, user-triggered diagnostics copy).
- Do not scaffold the Tauri app shell yet. It lands in weeks 5–9 per the dependency order. Building it early creates integration debt.
- Do not add `anyhow`, `eyre`, or any other error aggregation crate. `VaultError` is the one.
- Do not `unwrap()`. Ever. Clippy will reject it.
- Do not publish `docs/SPEC.md` before week 6. The format is a living draft until the Rust core has implemented it end-to-end. Publishing early commits us to a format that might still need to change.

## Skill routing

When the user's request matches an available gstack skill, invoke it via the Skill tool as your first action. Do not answer directly.

Key routing rules:

- Bugs, errors, "why is this broken", test failures → invoke `investigate`
- "Ship this", "create a PR", "push" → invoke `ship`
- "Review my diff", "check my changes" → invoke `review`
- "Test this", "QA this", "find bugs" → invoke `qa`
- "Plan this feature", architecture review → invoke `plan-eng-review`
- "Design review", visual polish → invoke `plan-design-review` or `design-review`
- "Save progress", checkpoint, resume → invoke `checkpoint`
- "Weekly retro" → invoke `retro`
