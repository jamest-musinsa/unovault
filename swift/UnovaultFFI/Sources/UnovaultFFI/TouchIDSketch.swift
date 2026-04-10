//
//  TouchIDSketch.swift
//
//  Design sketch for the Touch ID unlock path. This file is NOT wired
//  into the shipping bridge because running it requires a signed binary
//  with the `com.apple.developer.authentication-service.passkey-support`
//  entitlement. A real Apple Developer account is a prerequisite; see
//  the CEO plan's "Apple Developer enrollment in week 1" note.
//
//  What this file is for
//  ---------------------
//
//  Documenting the shape of the future Touch ID integration so week 5-6
//  reviewers can see exactly where it will plug in. Once entitlements
//  are available, move this file to `Sources/UnovaultFFI/TouchID.swift`,
//  add `UseTouchID` to the public API, and wire it up from Rust via a
//  callback interface.
//
//  The shape of the real integration
//  ----------------------------------
//
//  1. Rust side exposes a `Vault::unlock_with_key(bytes)` constructor
//     that accepts an already-derived 32-byte master key rather than a
//     password. Swift calls this after fetching the key from the
//     Secure Enclave-gated Keychain.
//
//  2. Swift holds the Keychain entry `app.unovault.fast-unlock-key` with
//     access control flags:
//
//         kSecAttrAccessibleWhenUnlockedThisDeviceOnly
//         SecAccessControlCreateWithFlags(
//             nil, .whenUnlockedThisDeviceOnly,
//             .biometryCurrentSet, nil)
//
//     The entry is seeded on first successful password unlock by
//     calling `Vault::export_fast_unlock_key()` (does NOT exist yet —
//     lands when entitlements arrive).
//
//  3. On subsequent app launches, Swift calls `LAContext.evaluatePolicy`
//     which gates the Keychain read. If Touch ID succeeds, Keychain
//     returns the wrapped master key, Swift hands the bytes to Rust via
//     `FfiVault.unlock_with_key`, and the vault opens in ~100-300ms
//     instead of ~500-1500ms (the argon2id cost on first unlock).
//
//  4. Fallback: if biometric fails OR the Keychain entry is missing
//     OR the biometric set has changed, Swift falls back to showing
//     the password field and `FfiVault.unlock` is used instead.
//
//  Security notes captured here so a reviewer can find them later
//  ---------------------------------------------------------------
//
//  * The Secure Enclave wrap only applies when the vault is opened from
//    the same device that created the Keychain entry. Time Machine
//    restore preserves the Keychain so the fast path still works.
//
//  * Manually copying the `.unovault` bundle to a different Mac does
//    NOT copy the Keychain entry. The second Mac has to use the
//    password path, which is by design — we do not want a stolen USB
//    drive to also unlock on the thief's machine.
//
//  * The `biometryCurrentSet` flag invalidates the Keychain entry if
//    the user adds or removes a fingerprint. The fallback path covers
//    this; the user enters the password once and the entry is re-seeded.

#if canImport(LocalAuthentication) && false  // disabled until entitlements arrive
import LocalAuthentication

/// Sketch of the future Touch ID unlock API. Currently behind
/// `#if ... && false` so it does not compile into the shipping
/// bridge. Kept here so the design is reviewable alongside the code
/// it will eventually replace.
public enum TouchIDSketch {
    public static func requestBiometricUnlock(reason: String) async throws -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            // No enrolled biometrics or hardware not available.
            return false
        }

        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, evalError in
                if let evalError {
                    continuation.resume(throwing: evalError)
                } else {
                    continuation.resume(returning: success)
                }
            }
        }
    }
}
#endif
