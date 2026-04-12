# `.unovault` Format Specification — v2

> **Status**: frozen at public beta. Breaking changes require a new format version.

This document describes the on-disk layout of a `.unovault` vault file,
the cryptographic envelope that protects it, and the event schema that
drives the LWW merge semantics. It is the reference a third-party
implementer needs to build a compatible reader or writer.

The canonical Rust implementation lives in `crates/unovault-core/`.

---

## 1. Bundle directory layout

A `.unovault` vault is a macOS bundle directory (registered via
`CFBundlePackageType = BNDL` in the design doc, though the format
itself is OS-agnostic):

```
default.unovault/
├── manifest.json          Immutable after creation, HMAC-protected
└── chunks/                Append-only encrypted event chunks
    ├── 00000001-<install-a>.chunk
    ├── 00000002-<install-a>.chunk
    ├── 00000001-<install-b>.chunk
    └── ...
```

* **`manifest.json`** is written once at vault creation and never
  modified again — except by the password/recovery rotation flows,
  which atomically rewrite it with a new MAC. iCloud Drive does not
  merge concurrent writes to JSON files; making the manifest
  effectively immutable sidesteps the problem.

* **`chunks/`** is append-only. Each chunk file contains a batch of
  encrypted events. Chunk filenames are
  `NNNNNNNN-<install-id>.chunk` where `NNNNNNNN` is a zero-padded
  hex counter and `<install-id>` is the authoring device's UUID.
  The counter is per-install; two devices can hold
  `00000001-aaaa.chunk` and `00000001-bbbb.chunk` side by side.

---

## 2. `manifest.json` — v2 schema

```json
{
  "format_version": 2,
  "schema_version": 1,
  "password_kdf": {
    "m_cost_kib": 262144,
    "t_cost": 3,
    "p_cost": 4
  },
  "password_salt_b64": "<16 bytes, unpadded URL-safe base64>",
  "password_wrapped_key_b64": "<72 bytes, unpadded URL-safe base64>",
  "recovery_kdf": { ... },
  "recovery_salt_b64": "<16 bytes, unpadded URL-safe base64>",
  "recovery_wrapped_key_b64": "<72 bytes, unpadded URL-safe base64>",
  "manifest_mac_b64": "<32 bytes, unpadded URL-safe base64>"
}
```

### 2.1 Key hierarchy (v2)

```
            master password               BIP39 recovery phrase
                  │                               │
          argon2id + password_salt        argon2id + recovery_salt
                  │                               │
                  ▼                               ▼
           password KEK                    recovery KEK
                  │                               │
      ┌───────────┘                               └───────────┐
      ▼                                                       ▼
  XChaCha20-Poly1305                                  XChaCha20-Poly1305
  wrap(master_key)                                    wrap(master_key)
      │                                                       │
      ▼                                                       ▼
  password_wrapped_key_b64                    recovery_wrapped_key_b64
                              │
                       master key (32 bytes, random)
                              │
                        HKDF-SHA256
                       ┌──────┴──────┐
                       ▼             ▼
                encryption key   mac key
                 (32 bytes)      (32 bytes)
```

* **Master key**: 32 bytes of OS CSPRNG entropy, generated once at
  vault creation.
* **KEK**: derived from the password (or recovery phrase) + a 16-byte
  salt via argon2id. Parameters stored in the manifest so older
  vaults keep working as we tune them.
* **Wrapped key**: `[nonce (24)] [ciphertext (32)] [tag (16)]` = 72
  bytes. XChaCha20-Poly1305 AEAD with the KEK as the key and the
  master key as the plaintext.
* **Sub-keys**: HKDF-SHA256 from the master key with domain-separated
  `info` strings: `unovault-v1/enc` for the encryption key,
  `unovault-v1/mac` for the MAC key.
* **Recovery slot**: optional. Vaults created without a recovery
  phrase omit the `recovery_*` fields entirely.

### 2.2 Manifest MAC

The `manifest_mac_b64` field is HMAC-SHA256 over the "canonical body"
— the manifest JSON with `manifest_mac_b64` set to the empty string.
Computed using the MAC sub-key derived from the master key.

### 2.3 Unlock flow

1. Parse `manifest.json`.
2. Derive the KEK from the user's password (or recovery phrase) +
   salt + KDF params.
3. Unwrap the master key via XChaCha20-Poly1305. AEAD failure ⇒
   wrong password.
4. Derive sub-keys from the master key via HKDF.
5. Verify the manifest MAC over the canonical body. Failure ⇒
   corrupted/tampered manifest.
6. Read + decrypt all chunks; sort events; fold into item state.

---

## 3. Chunk file byte layout

Each `.chunk` file is a single AEAD-encrypted blob with a magic
header for format identification:

```
Offset  Length  Content
──────  ──────  ──────────────────────────────
 0       4      Magic bytes "UVLT" (0x55564C54)
 4       2      format_version, u16 little-endian (currently 2)
 6      24      XChaCha20 nonce
30       *      Ciphertext + Poly1305 tag (16 bytes at the end)
```

The plaintext of the AEAD envelope is a `postcard`-serialized
`Vec<Event>`. postcard is a compact, deterministic binary format
from the Rust ecosystem; third-party implementers can use any
postcard-compatible deserializer.

---

## 4. Event schema

Events are the atomic unit of state change. Every modification to
the vault — create item, update field, delete item — produces one
`Event`. Events are immutable after creation and never rewritten.

```rust
struct Event {
    install_id: Uuid,      // 16 bytes, identifies the authoring device
    lamport: u64,          // per-install monotonic counter
    timestamp_ms: u64,     // wall-clock ms since Unix epoch
    op: Op,
}

enum Op {
    CreateItem { item_id: Uuid, initial: ItemSnapshot },
    UpdateField { item_id: Uuid, field: FieldKey, value: FieldValue },
    DeleteItem { item_id: Uuid },
}

struct ItemSnapshot {
    title: String,
    kind: ItemKind,
    username: Option<String>,
    url: Option<String>,
}

enum ItemKind {
    Password, Passkey, Totp, SshKey, ApiToken, SecureNote,
}

enum FieldKey {
    Title, Username, Url, Password, TotpSecret, Notes, Kind,
    Custom(String),
}

enum FieldValue {
    Text(String),
    Bytes(Vec<u8>),
    Tombstone,
    Kind(ItemKind),
}
```

### 4.1 Event ordering (LWW)

Events are sorted by a 3-tuple before folding:

```
(timestamp_ms, install_id, lamport)
```

All three are compared numerically / lexicographically. The latest
event for a given `(item_id, field_key)` wins — this is the
Last-Writer-Wins (LWW) merge rule.

### 4.2 Folding

Starting from an empty state, events are applied in sorted order:

* `CreateItem` adds a new item to the state.
* `UpdateField` sets a single field on an existing item. A
  `FieldValue::Tombstone` deletes the field.
* `DeleteItem` removes the item entirely. Any subsequent
  `UpdateField` for that item is dropped.

The result is a deterministic map of `item_id → ItemState`.

---

## 5. Sync semantics

Sync is append-only file delivery. The only files that travel
between devices are chunk files in `chunks/`. The manifest is NOT
synced — it is created once per vault and lives on every device
that has a copy.

Two devices sharing a vault:

1. Device A writes chunks with filenames like `00000001-<A>.chunk`.
2. Device B writes chunks with filenames like `00000001-<B>.chunk`.
3. iCloud Drive (or any file-sync service) delivers A's chunks to
   B and vice versa.
4. Each device reads the other's chunks, decrypts them, and folds
   the combined event stream.
5. Because chunk filenames are sharded by install ID, there are
   no filename collisions.
6. Because event ordering is by `(timestamp, install, lamport)`,
   the merged fold is deterministic regardless of delivery order.

---

## 6. Writing a third-party client

To build a compatible reader:

1. Parse `manifest.json` as the JSON schema in section 2.
2. Derive the KEK from the user's password + salt + KDF params
   via argon2id.
3. Unwrap the master key via XChaCha20-Poly1305 (24-byte nonce).
4. Derive sub-keys via HKDF-SHA256 from the master key.
5. For each `.chunk` file: strip the 6-byte header, decrypt the
   remainder via XChaCha20-Poly1305 using the encryption sub-key.
6. Deserialize the plaintext as a postcard `Vec<Event>`.
7. Sort all events by `(timestamp_ms, install_id, lamport)`.
8. Fold per section 4.2.

To build a compatible writer: follow the same steps for reading,
then produce new `Event` values, serialize with postcard, encrypt,
and write a new chunk file with a fresh counter.

---

## 7. Stability policy

The **v2 format is frozen at public beta**. Any change that would
cause an older reader to misinterpret a vault requires a new
`format_version` (v3+). Additive changes to the event schema (new
`FieldKey` variants, new `Op` variants) that older readers can
safely ignore do NOT bump the format version — they bump
`schema_version` instead.
