# swift/

Swift package that wraps the `unovault-core` Rust vault engine via UniFFI.

## Layout

```
swift/
├── generated/                 # uniffi-bindgen output, regenerated on demand
│   ├── unovault_ffi.swift     # Swift bindings (copied into UnovaultFFI/Sources/UnovaultFFI/)
│   ├── unovault_ffiFFI.h      # C header for the cdylib
│   └── unovault_ffiFFI.modulemap
└── UnovaultFFI/               # Swift Package that consumes the generated bindings
    ├── Package.swift
    ├── Sources/
    │   ├── UnovaultFFI/       # Swift target — one file is the uniffi-generated wrapper
    │   │   ├── UnovaultFFI.swift
    │   │   └── TouchIDSketch.swift   # design sketch, disabled until entitlements arrive
    │   └── UnovaultFFIC/      # System-library target — the C header + modulemap
    │       ├── unovault_ffiFFI.h
    │       └── module.modulemap
    └── Tests/UnovaultFFITests/
        └── UnovaultFFITests.swift    # end-to-end smoke tests
```

## Building + testing

```sh
# From the repo root:
cargo build -p unovault-ffi                             # produces libunovault_ffi.dylib under target/debug

# Regenerate Swift bindings if the Rust FFI surface changed:
cargo run -p uniffi-bindgen -- generate \
    --library target/debug/libunovault_ffi.dylib \
    --language swift \
    --out-dir swift/generated
cp swift/generated/unovault_ffi.swift      swift/UnovaultFFI/Sources/UnovaultFFI/UnovaultFFI.swift
cp swift/generated/unovault_ffiFFI.h       swift/UnovaultFFI/Sources/UnovaultFFIC/unovault_ffiFFI.h
# module.modulemap is stable, no need to copy.

# Run the Swift smoke tests:
cd swift/UnovaultFFI
swift test
```

The test target expects `libunovault_ffi.dylib` to exist under
`../../target/debug`. `swift test` in debug mode will link against that
dylib via the `linkerSettings.unsafeFlags` in `Package.swift`. For a
release build, point `-L` at `target/release` and re-run.

## What works today (Week 5-6)

- `FfiVault.create` / `FfiVault.unlock` — full lifecycle
- `addItem`, `setPassword`, `setNotes`, `save`, `listItems`, `itemCount`
- `ffiVersion` and `formatVersion` free functions
- `FfiError` variants cleanly surface the `VaultError` category
- Every smoke test passes end-to-end through the FFI boundary (~25s
  runtime dominated by argon2id at production params)

## What does NOT work yet (documented, deferred)

- **Touch ID unlock** — sketched in `TouchIDSketch.swift` but disabled
  via `#if ... && false`. Needs Apple Developer entitlements to run.
- **Secure Enclave fast-path key** — same blocker.
- **iCloud `NSMetadataQuery` file watcher** — needs iCloud container
  entitlement. The `FileSystemBackend` trait in `unovault-core/src/sync.rs`
  is the seam where the real iCloud backend will plug in.
- **Password reveal via native overlay** — needs a Swift-side callback
  the Rust core can invoke. Lands alongside the Tauri UI in weeks 7-9.
- **`.xcframework` packaging** — needs Xcode. The current `Package.swift`
  assumes local cargo builds; packaging for distribution is a CI job
  for the week 24 polish + beta sprint.

## For reviewers

The bridge gate for week 5-6 is **"does Swift see the Rust vault"** and
the answer is yes. Run `swift test` from `swift/UnovaultFFI` and the
five XCTests run Rust crypto, argon2id, manifest writing, chunk I/O, and
LWW event serialization — the entire vault engine from the Swift side
of the boundary. If this passes on CI, the bridge spike is accepted.
