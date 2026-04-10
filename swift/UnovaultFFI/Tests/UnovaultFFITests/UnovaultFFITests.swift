//
//  UnovaultFFITests.swift
//
//  End-to-end smoke test for the Rust ↔ Swift bridge. If every test in
//  this file passes, the Week 5-6 UniFFI bridge gate is satisfied.
//
//  What each test proves:
//
//    * `testFfiVersion_returnsNonEmpty`:
//        The free-function FFI entry point works. Proves the dylib is
//        loaded and the uniffi scaffolding is registered.
//
//    * `testFormatVersion_matchesRustConstant`:
//        Primitive u16 return value round-trips correctly through the
//        FFI boundary.
//
//    * `testCreateAddListSave_roundTrip`:
//        The full vault lifecycle through the Swift API — create a new
//        vault in a temp directory, add an item, list it back, save.
//        Exercises Object, Record, Enum, Option<String>, Result<T, E>,
//        and the argon2id path in one go.
//
//    * `testReopenAfterSave_preservesData`:
//        Drop the Swift vault (triggers Rust Drop which zeroizes keys),
//        then re-open with the same password. Every item must come
//        back intact. This is the "Week 4 gate, but through Swift"
//        test.
//
//    * `testUnlockWithWrongPassword_surfacesUserActionableError`:
//        Error mapping from VaultError::UserActionable to FfiError.UserActionable
//        survives the boundary and reaches Swift as a typed catch.

import XCTest
@testable import UnovaultFFI

final class UnovaultFFITests: XCTestCase {

    // MARK: - Helpers

    /// Produces a unique temporary directory path for each test so test
    /// runs do not interfere with each other.
    private func makeTempDir() -> URL {
        let base = FileManager.default.temporaryDirectory
        let unique = base.appendingPathComponent("unovault-ffi-test-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: unique, withIntermediateDirectories: true)
        return unique
    }

    private func paths() -> (bundle: String, installDir: String, cleanup: () -> Void) {
        let root = makeTempDir()
        let bundle = root.appendingPathComponent("test.unovault").path
        let installDir = root.appendingPathComponent("install").path
        let cleanup: () -> Void = {
            _ = try? FileManager.default.removeItem(at: root)
        }
        return (bundle, installDir, cleanup)
    }

    // MARK: - Free functions

    func testFfiVersion_returnsNonEmpty() {
        let version = ffiVersion()
        XCTAssertFalse(version.isEmpty, "FFI version string should not be empty")
        XCTAssertTrue(version.first?.isNumber ?? false, "version should start with a digit: \(version)")
    }

    func testFormatVersion_matchesRustConstant() {
        let v = formatVersion()
        XCTAssertEqual(v, 1, "v1 format is expected at week 5-6; bump this assertion when the format moves")
    }

    // MARK: - Vault lifecycle

    func testCreateAddListSave_roundTrip() throws {
        let (bundle, installDir, cleanup) = paths()
        defer { cleanup() }

        let vault = try FfiVault.create(
            bundlePath: bundle,
            password: "hunter2",
            installIdDir: installDir
        )

        XCTAssertEqual(try vault.itemCount(), 0, "fresh vault should have zero items")

        let id = try vault.addItem(
            title: "GitHub",
            kind: .password,
            username: "james@personal",
            url: "github.com"
        )
        XCTAssertFalse(id.isEmpty, "add_item should return a non-empty UUID string")

        // UUID parse sanity-check — proves the Rust side emitted a real UUID.
        XCTAssertNotNil(UUID(uuidString: id), "returned id should parse as UUID: \(id)")

        let setSuccess = try vault.setPassword(itemId: id, password: "correct horse battery staple")
        XCTAssertTrue(setSuccess, "set_password on a real item should return true")

        XCTAssertEqual(try vault.itemCount(), 1)

        let summaries = try vault.listItems()
        XCTAssertEqual(summaries.count, 1)
        XCTAssertEqual(summaries[0].id, id)
        XCTAssertEqual(summaries[0].title, "GitHub")
        XCTAssertEqual(summaries[0].kind, .password)
        XCTAssertEqual(summaries[0].username, "james@personal")
        XCTAssertEqual(summaries[0].url, "github.com")
        XCTAssertTrue(summaries[0].hasPassword)
        XCTAssertFalse(summaries[0].hasTotp)

        try vault.save()
    }

    func testReopenAfterSave_preservesData() throws {
        let (bundle, installDir, cleanup) = paths()
        defer { cleanup() }

        let savedItemId: String
        do {
            let vault = try FfiVault.create(
                bundlePath: bundle,
                password: "hunter2",
                installIdDir: installDir
            )
            savedItemId = try vault.addItem(
                title: "Linear",
                kind: .passkey,
                username: "james@personal",
                url: "linear.app"
            )
            try vault.save()
            // vault goes out of scope → Arc<FfiVault> dropped in Rust → keys zeroized.
        }

        let reopened = try FfiVault.unlock(
            bundlePath: bundle,
            password: "hunter2",
            installIdDir: installDir
        )

        XCTAssertEqual(try reopened.itemCount(), 1, "reopen should see the saved item")

        let summaries = try reopened.listItems()
        XCTAssertEqual(summaries.count, 1)
        XCTAssertEqual(summaries[0].id, savedItemId)
        XCTAssertEqual(summaries[0].title, "Linear")
        XCTAssertEqual(summaries[0].kind, .passkey)
    }

    func testUnlockWithWrongPassword_surfacesUserActionableError() throws {
        let (bundle, installDir, cleanup) = paths()
        defer { cleanup() }

        // Create + populate with the correct password.
        do {
            let vault = try FfiVault.create(
                bundlePath: bundle,
                password: "correct",
                installIdDir: installDir
            )
            _ = try vault.addItem(title: "anything", kind: .password, username: nil, url: nil)
            try vault.save()
        }

        XCTAssertThrowsError(
            try FfiVault.unlock(bundlePath: bundle, password: "wrong", installIdDir: installDir)
        ) { error in
            guard case FfiError.UserActionable(let message) = error else {
                XCTFail("expected FfiError.UserActionable, got \(error)")
                return
            }
            XCTAssertFalse(message.isEmpty, "error should carry a log message")
        }
    }
}
