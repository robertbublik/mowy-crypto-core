// Connects the fixed UniFFI proof façade to Keychain and protected namespaces.

import Foundation
#if canImport(UIKit)
import UIKit
#endif

final class MowyNativeProtectedKeyStore: NativeProtectedKeyStore, @unchecked Sendable {
    private static let directoryNames = [
        "source",
        "ciphertext",
        "receive-temp",
        "verified",
        "archive",
    ]

    private let keyStore: MowyProtectedKeyStore
    private let fileManager: FileManager
    private let isProtectedDataAvailable: () -> Bool
    private let lock = NSLock()
    private var activeToken: UInt64?
    private var activeMaterial: Data?
    private var nextToken: UInt64 = 1

    init(
        keyStore: MowyProtectedKeyStore = MowyProtectedKeyStore(),
        fileManager: FileManager = .default,
        protectedDataAvailable: @escaping () -> Bool = {
#if canImport(UIKit)
            UIApplication.shared.isProtectedDataAvailable
#else
            false
#endif
        }
    ) {
        self.keyStore = keyStore
        self.fileManager = fileManager
        self.isProtectedDataAvailable = protectedDataAvailable
    }

    func protectedDataAvailable() -> NativeBridgeResponse {
        success(flag: isProtectedDataAvailable())
    }

    func keyState() -> NativeBridgeResponse {
        response {
            let state = try keyStore.state()
            return success(
                keyState: state == .present ? .present : .absent
            )
        }
    }

    func installationMarkerExists() -> NativeBridgeResponse {
        response {
            success(flag: try rootURL().appendingPathComponent("installation.v1").isRegularFile())
        }
    }

    func databaseExists() -> NativeBridgeResponse {
        response {
            success(flag: try rootURL().appendingPathComponent("operations.sqlite3").isRegularFile())
        }
    }

    func prepareNamespaces() -> NativeBridgeResponse {
        response {
            try requireProtectedData()
            let root = try rootURL()
            try ensureApplicationSupportDirectory(root.deletingLastPathComponent().deletingLastPathComponent())
            try ensurePrivateDirectory(root.deletingLastPathComponent())
            try ensurePrivateDirectory(root)
            for name in Self.directoryNames {
                try ensurePrivateDirectory(root.appendingPathComponent(name, isDirectory: true))
            }
            try requireProtectedData()
            return success(path: root.path)
        }
    }

    func commitCompanions() -> NativeBridgeResponse {
        response {
            try requireProtectedData()
            let root = try rootURL()
            let marker = root.appendingPathComponent("installation.v1")
            let database = root.appendingPathComponent("operations.sqlite3")
            let markerExists = try marker.isRegularFile()
            let databaseExists = try database.isRegularFile()
            if markerExists && databaseExists {
                return success()
            }
            guard !markerExists && !databaseExists else {
                throw MowyProofPlatformError.unavailable
            }
            try createPrivateFile(marker)
            try createPrivateFile(database)
            try requireProtectedData()
            return success()
        }
    }

    func storeNew(
        word0: UInt64,
        word1: UInt64,
        word2: UInt64,
        word3: UInt64,
        word4: UInt64,
        word5: UInt64,
        word6: UInt64,
        word7: UInt64,
        word8: UInt64,
        word9: UInt64,
        word10: UInt64,
        word11: UInt64
    ) -> NativeBridgeResponse {
        response {
            var words = [
                word0, word1, word2, word3, word4, word5,
                word6, word7, word8, word9, word10, word11,
            ]
            defer {
                _ = words.withUnsafeMutableBytes {
                    $0.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }
            var material = Data(capacity: MowyProtectedKeyStore.rootKeyMaterialBytes)
            defer { material.resetBytes(in: 0..<material.count) }
            for word in words {
                for shift in stride(from: 56, through: 0, by: -8) {
                    material.append(UInt8((word >> UInt64(shift)) & 0xff))
                }
            }
            try keyStore.storeNew(material)
            return success()
        }
    }

    func beginLoad() -> NativeBridgeResponse {
        response {
            try requireProtectedData()
            lock.lock()
            defer { lock.unlock() }
            guard activeMaterial == nil, activeToken == nil else {
                throw MowyProofPlatformError.conflict
            }
            let material = try keyStore.load()
            guard material.count == MowyProtectedKeyStore.rootKeyMaterialBytes else {
                throw MowyProofPlatformError.unavailable
            }
            let token = nextToken
            nextToken = nextToken == UInt64.max ? 1 : nextToken + 1
            activeToken = token
            activeMaterial = material
            return success(number: token)
        }
    }

    func loadWord(token: UInt64, index: UInt8) -> NativeBridgeResponse {
        response {
            lock.lock()
            defer { lock.unlock() }
            guard activeToken == token, let material = activeMaterial, index < 12 else {
                throw MowyProofPlatformError.invalidInput
            }
            let start = Int(index) * 8
            var word: UInt64 = 0
            for offset in 0..<8 {
                word = (word << 8) | UInt64(material[start + offset])
            }
            return success(number: word)
        }
    }

    func finishLoad(token: UInt64) -> NativeBridgeResponse {
        response {
            lock.lock()
            defer { lock.unlock() }
            guard activeToken == token, var material = activeMaterial else {
                throw MowyProofPlatformError.conflict
            }
            material.resetBytes(in: 0..<material.count)
            activeMaterial = nil
            activeToken = nil
            return success()
        }
    }

    private func rootURL() throws -> URL {
        guard let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw MowyProofPlatformError.storage
        }
        return applicationSupport
            .appendingPathComponent("app.mowy.prototype.p2", isDirectory: true)
            .appendingPathComponent("proof-v1", isDirectory: true)
    }

    private func ensurePrivateDirectory(_ url: URL) throws {
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else { throw MowyProofPlatformError.unavailable }
            let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { throw MowyProofPlatformError.unavailable }
        } else {
            try fileManager.createDirectory(
                at: url,
                withIntermediateDirectories: false,
                attributes: [
                    .posixPermissions: 0o700,
                    .protectionKey: FileProtectionType.complete,
                ]
            )
        }
        try fileManager.setAttributes(
            [
                .posixPermissions: 0o700,
                .protectionKey: FileProtectionType.complete,
            ],
            ofItemAtPath: url.path
        )
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(resourceValues)
    }

    private func ensureApplicationSupportDirectory(_ url: URL) throws {
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else { throw MowyProofPlatformError.unavailable }
            let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { throw MowyProofPlatformError.unavailable }
            return
        }
        try fileManager.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: nil
        )
    }

    private func createPrivateFile(_ url: URL) throws {
        guard fileManager.createFile(
            atPath: url.path,
            contents: Data(),
            attributes: [
                .posixPermissions: 0o600,
                .protectionKey: FileProtectionType.complete,
            ]
        ) else {
            throw MowyProofPlatformError.conflict
        }
        let handle = try FileHandle(forWritingTo: url)
        try handle.synchronize()
        try handle.close()
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(resourceValues)
    }

    private func requireProtectedData() throws {
        guard isProtectedDataAvailable() else { throw MowyProofPlatformError.unavailable }
    }

    private func response(_ operation: () throws -> NativeBridgeResponse) -> NativeBridgeResponse {
        do {
            return try operation()
        } catch let error as MowyProtectedKeyStoreError {
            switch error {
            case .unavailable, .corruptState:
                return failure(.unavailable)
            case .conflict:
                return failure(.conflict)
            case .storage:
                return failure(.storage)
            }
        } catch let error as MowyProofPlatformError {
            return failure(error.code)
        } catch {
            return failure(.storage)
        }
    }
}

final class MowyProofCancellation: MowyCancellation, @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    func isCancelled() -> NativeBridgeResponse {
        lock.lock()
        let current = cancelled
        lock.unlock()
        return success(flag: current)
    }
}

enum MowyDevelopmentProofRunner {
    static func publish(now: UInt64) -> MowyPublicBundleResult {
        publishDevelopmentBundle(
            protectedStore: MowyNativeProtectedKeyStore(),
            now: now
        )
    }

    static func prepare(
        cancellation: MowyProofCancellation,
        now: UInt64,
        plaintextLength: UInt64,
        recipientBundle: MowyPublicBundle
    ) -> MowyPreparedTransferResult {
        prepareDevelopmentTransfer(
            protectedStore: MowyNativeProtectedKeyStore(),
            cancellation: cancellation,
            now: now,
            plaintextLength: plaintextLength,
            recipientBundle: recipientBundle
        )
    }

    static func stage(
        now: UInt64,
        senderBundle: MowyPublicBundle,
        transfer: MowyDevelopmentTransfer
    ) -> MowyStagedTransferResult {
        stageDevelopmentTransfer(
            protectedStore: MowyNativeProtectedKeyStore(),
            now: now,
            senderBundle: senderBundle,
            transfer: transfer
        )
    }

    static func resume(
        cancellation: MowyProofCancellation,
        now: UInt64,
        receiverOperationId: String
    ) -> MowyProofResult {
        resumeDevelopmentTransfer(
            protectedStore: MowyNativeProtectedKeyStore(),
            cancellation: cancellation,
            now: now,
            receiverOperationId: receiverOperationId
        )
    }

    static func cleanupSender(
        now: UInt64,
        transfer: MowyDevelopmentTransfer
    ) -> MowyCodeResult {
        cleanupDevelopmentSender(
            protectedStore: MowyNativeProtectedKeyStore(),
            now: now,
            transfer: transfer
        )
    }

}

enum MowyDevelopmentProofCodec {
    static func encode(_ bundle: MowyPublicBundle) -> String {
        [
            bundle.accountId,
            bundle.deviceId,
            bundle.agreementKeyId,
            bundle.identityPublicKey,
            bundle.agreementPublicKey,
            String(bundle.notBefore),
            String(bundle.notAfter),
            bundle.signature,
        ].joined(separator: "|")
    }

    static func decodeBundle(_ value: String) -> MowyPublicBundle? {
        let fields = value.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 8,
              let notBefore = UInt64(fields[5]),
              let notAfter = UInt64(fields[6]) else {
            return nil
        }
        return MowyPublicBundle(
            accountId: fields[0],
            deviceId: fields[1],
            agreementKeyId: fields[2],
            identityPublicKey: fields[3],
            agreementPublicKey: fields[4],
            notBefore: notBefore,
            notAfter: notAfter,
            signature: fields[7]
        )
    }

    static func encode(_ transfer: MowyDevelopmentTransfer) -> String {
        [
            transfer.senderOperationId,
            transfer.receiverOperationId,
            transfer.conversationId,
            transfer.assetId,
            transfer.recipientKeyId,
            transfer.sealedManifest,
            String(transfer.plaintextLength),
            String(transfer.ciphertextLength),
            transfer.ciphertextSha256,
        ].joined(separator: "|")
    }

    static func decodeTransfer(_ value: String) -> MowyDevelopmentTransfer? {
        let fields = value.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 9,
              let plaintextLength = UInt64(fields[6]),
              let ciphertextLength = UInt64(fields[7]) else {
            return nil
        }
        return MowyDevelopmentTransfer(
            senderOperationId: fields[0],
            receiverOperationId: fields[1],
            conversationId: fields[2],
            assetId: fields[3],
            recipientKeyId: fields[4],
            sealedManifest: fields[5],
            plaintextLength: plaintextLength,
            ciphertextLength: ciphertextLength,
            ciphertextSha256: fields[8]
        )
    }
}

private enum MowyProofPlatformError: Error {
    case invalidInput
    case unavailable
    case conflict
    case storage

    var code: MowyCoreCode {
        switch self {
        case .invalidInput: .invalidInput
        case .unavailable: .unavailable
        case .conflict: .conflict
        case .storage: .storage
        }
    }
}

private func success(
    flag: Bool = false,
    number: UInt64 = 0,
    keyState: NativeProtectedKeyState = .absent,
    path: String = ""
) -> NativeBridgeResponse {
    NativeBridgeResponse(
        code: .success,
        flag: flag,
        number: number,
        keyState: keyState,
        path: path
    )
}

private func failure(_ code: MowyCoreCode) -> NativeBridgeResponse {
    NativeBridgeResponse(
        code: code,
        flag: false,
        number: 0,
        keyState: .absent,
        path: ""
    )
}

private extension URL {
    func isRegularFile() throws -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        let values = try resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey,
        ])
        return values.isRegularFile == true && values.isSymbolicLink != true
    }
}
