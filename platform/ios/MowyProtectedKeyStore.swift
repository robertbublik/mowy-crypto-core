// Owns the P2 Keychain item inside the public native core; no JavaScript API
// receives the 96-byte value handled by this file.

import Foundation
import Security
#if canImport(UIKit)
import UIKit
#endif

enum MowyProtectedKeyStoreError: Error, Equatable {
    case unavailable
    case corruptState
    case conflict
    case storage
}

enum MowyProtectedKeyState: Equatable {
    case absent
    case present
}

protocol MowyKeychainBackend {
    func add(query: [String: Any], data: Data) -> OSStatus
    func read(query: [String: Any]) -> (OSStatus, Data?)
    func exists(query: [String: Any]) -> OSStatus
    func delete(query: [String: Any]) -> OSStatus
}

struct MowySystemKeychainBackend: MowyKeychainBackend {
    func add(query: [String: Any], data: Data) -> OSStatus {
        var attributes = query
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecValueData as String] = data
        return SecItemAdd(attributes as CFDictionary, nil)
    }

    func read(query: [String: Any]) -> (OSStatus, Data?) {
        var readQuery = query
        readQuery[kSecReturnData as String] = kCFBooleanTrue
        readQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(readQuery as CFDictionary, &result)
        return (status, result as? Data)
    }

    func exists(query: [String: Any]) -> OSStatus {
        var existenceQuery = query
        existenceQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(existenceQuery as CFDictionary, nil)
    }

    func delete(query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }
}

final class MowyProtectedKeyStore {
    static let rootKeyMaterialBytes = 96

    private let backend: MowyKeychainBackend
    private let protectedDataAvailable: () -> Bool
    private let query: [String: Any]

    init(
        backend: MowyKeychainBackend = MowySystemKeychainBackend(),
        protectedDataAvailable: @escaping () -> Bool = {
#if canImport(UIKit)
            UIApplication.shared.isProtectedDataAvailable
#else
            false
#endif
        }
    ) {
        self.backend = backend
        self.protectedDataAvailable = protectedDataAvailable
        self.query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "app.mowy.prototype.p2.keys.v1",
            kSecAttrAccount as String: "root-key-material-v1",
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
    }

    /// Inspection never treats a locked Keychain item as absent.
    func state() throws -> MowyProtectedKeyState {
        try requireProtectedData()
        let status = backend.exists(query: query)
        try requireProtectedData()
        switch status {
        case errSecSuccess:
            return .present
        case errSecItemNotFound:
            return .absent
        case errSecInteractionNotAllowed, errSecNotAvailable:
            throw MowyProtectedKeyStoreError.unavailable
        default:
            throw MowyProtectedKeyStoreError.storage
        }
    }

    /// Creates one non-synchronizing, device-only item and never overwrites it.
    func storeNew(_ material: Data) throws {
        guard material.count == Self.rootKeyMaterialBytes else {
            throw MowyProtectedKeyStoreError.corruptState
        }
        try requireProtectedData()
        guard try state() == .absent else {
            throw MowyProtectedKeyStoreError.conflict
        }
        try requireProtectedData()

        let status = backend.add(query: query, data: material)
        guard status == errSecSuccess else {
            if status == errSecDuplicateItem {
                throw MowyProtectedKeyStoreError.conflict
            }
            if status == errSecInteractionNotAllowed || status == errSecNotAvailable {
                throw MowyProtectedKeyStoreError.unavailable
            }
            throw MowyProtectedKeyStoreError.storage
        }

        guard protectedDataAvailable() else {
            _ = backend.delete(query: query)
            throw MowyProtectedKeyStoreError.unavailable
        }
    }

    /// Loads exactly one item and rechecks protected-data state before return.
    func load() throws -> Data {
        try requireProtectedData()
        let (status, data) = backend.read(query: query)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw MowyProtectedKeyStoreError.unavailable
            }
            if status == errSecInteractionNotAllowed || status == errSecNotAvailable {
                throw MowyProtectedKeyStoreError.unavailable
            }
            throw MowyProtectedKeyStoreError.storage
        }
        guard var data else {
            throw MowyProtectedKeyStoreError.corruptState
        }
        guard data.count == Self.rootKeyMaterialBytes else {
            data.resetBytes(in: 0..<data.count)
            throw MowyProtectedKeyStoreError.corruptState
        }
        guard protectedDataAvailable() else {
            data.resetBytes(in: 0..<data.count)
            throw MowyProtectedKeyStoreError.unavailable
        }
        return data
    }

    private func requireProtectedData() throws {
        guard protectedDataAvailable() else {
            throw MowyProtectedKeyStoreError.unavailable
        }
    }
}
