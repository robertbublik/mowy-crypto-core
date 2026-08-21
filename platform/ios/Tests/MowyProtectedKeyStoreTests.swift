// Exercises Keychain failure mapping with a fake backend; physical-device
// checks separately prove the real accessibility class.

import Foundation
import Security
import XCTest
@testable import MowyProtectedKeyStorage

final class MowyProtectedKeyStoreTests: XCTestCase {
    func testRoundTripAndDuplicateRejection() throws {
        let backend = FakeKeychainBackend()
        let store = MowyProtectedKeyStore(backend: backend, protectedDataAvailable: { true })
        let material = Data(repeating: 0xA5, count: MowyProtectedKeyStore.rootKeyMaterialBytes)

        try store.storeNew(material)
        XCTAssertEqual(try store.load(), material)
        XCTAssertThrowsError(try store.storeNew(material)) { error in
            XCTAssertEqual(error as? MowyProtectedKeyStoreError, .conflict)
        }
    }

    func testLockedDeviceDoesNotTouchKeychain() {
        let backend = FakeKeychainBackend()
        let store = MowyProtectedKeyStore(backend: backend, protectedDataAvailable: { false })

        XCTAssertThrowsError(try store.storeNew(Data(repeating: 1, count: 96))) { error in
            XCTAssertEqual(error as? MowyProtectedKeyStoreError, .unavailable)
        }
        XCTAssertEqual(backend.calls, 0)
    }

    func testLockTransitionRollsBackNewItem() {
        let backend = FakeKeychainBackend()
        var checks = 0
        let store = MowyProtectedKeyStore(backend: backend) {
            checks += 1
            return checks < 5
        }

        XCTAssertThrowsError(try store.storeNew(Data(repeating: 2, count: 96))) { error in
            XCTAssertEqual(error as? MowyProtectedKeyStoreError, .unavailable)
        }
        XCTAssertNil(backend.item)
    }

    func testCorruptLengthIsRejected() throws {
        let backend = FakeKeychainBackend()
        backend.item = Data(repeating: 3, count: 95)
        let store = MowyProtectedKeyStore(backend: backend, protectedDataAvailable: { true })

        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? MowyProtectedKeyStoreError, .corruptState)
        }
    }
}

private final class FakeKeychainBackend: MowyKeychainBackend {
    var item: Data?
    var calls = 0

    func add(query: [String: Any], data: Data) -> OSStatus {
        calls += 1
        guard item == nil else { return errSecDuplicateItem }
        item = data
        return errSecSuccess
    }

    func read(query: [String: Any]) -> (OSStatus, Data?) {
        calls += 1
        guard let item else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, item)
    }

    func exists(query: [String: Any]) -> OSStatus {
        calls += 1
        return item == nil ? errSecItemNotFound : errSecSuccess
    }

    func delete(query: [String: Any]) -> OSStatus {
        calls += 1
        item = nil
        return errSecSuccess
    }
}
