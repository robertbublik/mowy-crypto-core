// Runs only the deterministic public P2 fixture and renders a coarse result.

import UIKit
import Darwin.Mach

@main
final class ProofAppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = ProofViewController()
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
}

final class ProofViewController: UIViewController {
    private let cancellation = MowyProofCancellation()
    private let resultLabel = UILabel()
    private var started = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        resultLabel.translatesAutoresizingMaskIntoConstraints = false
        resultLabel.numberOfLines = 0
        resultLabel.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        resultLabel.text = "Mowy P2 proof: running"
        view.addSubview(resultLabel)
        NSLayoutConstraint.activate([
            resultLabel.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 20),
            resultLabel.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -20),
            resultLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 24),
        ])
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !started else { return }
        started = true
        if let mode = argument("--mode") {
            if mode == "resume-relock-probe", !prepareRelockProbeReceipt() {
                publishToScreen("Mowy P2 relock probe: RECEIPT_PREPARATION_FAILED")
                return
            }
            DispatchQueue.global(qos: .userInitiated).async { [cancellation] in
                let result = self.runDevelopmentCommand(mode: mode, cancellation: cancellation)
                if mode == "resume-relock-probe" {
                    _ = self.publishRelockProbe(result)
                } else {
                    self.publish(result)
                }
            }
            return
        }
        guard let cycles = requestedCycles() else {
            publish("Mowy P2 proof: INVALID_INPUT")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [cancellation] in
            let warmup = autoreleasepool {
                runDevelopmentProof(
                    protectedStore: MowyNativeProtectedKeyStore(),
                    cancellation: cancellation,
                    now: UInt64(Date().timeIntervalSince1970),
                    plaintextLength: 26_214_400
                )
            }
            guard warmup.code == .success, warmup.receipt != nil else {
                self.publish(
                    "Mowy P2 proof: \(String(describing: warmup.code).uppercased())\n" +
                    "warmup_completed=false"
                )
                return
            }
            let baseline = currentResidentBytes()
            var lines = [
                "Mowy P2 proof: running",
                "warmup_completed=true",
                "cycles_requested=\(cycles)",
                "baseline_resident_bytes=\(baseline)",
            ]
            var completed = 0
            var code = MowyCoreCode.success
            for cycle in 1...cycles {
                let result = autoreleasepool {
                    runDevelopmentProof(
                        protectedStore: MowyNativeProtectedKeyStore(),
                        cancellation: cancellation,
                        now: UInt64(Date().timeIntervalSince1970),
                        plaintextLength: 26_214_400
                    )
                }
                code = result.code
                guard code == .success, let receipt = result.receipt else { break }
                completed += 1
                let resident = currentResidentBytes()
                lines.append("cycle_\(cycle)_id=\(receipt.proofId)")
                lines.append("cycle_\(cycle)_plaintext=\(receipt.plaintextLength)")
                lines.append("cycle_\(cycle)_ciphertext=\(receipt.ciphertextLength)")
                lines.append("cycle_\(cycle)_ciphertext_sha256=\(receipt.ciphertextSha256)")
                lines.append("cycle_\(cycle)_archive_sha256=\(receipt.archiveSha256)")
                lines.append("cycle_\(cycle)_resident_bytes=\(resident)")
            }
            let peak = peakResidentBytes()
            let finalResident = currentResidentBytes()
            let peakGrowth = peak >= baseline ? peak - baseline : 0
            let finalGrowth = finalResident >= baseline ? finalResident - baseline : 0
            let memoryWithinBounds = peakGrowth <= 100 * 1_024 * 1_024 &&
                finalGrowth <= 20 * 1_024 * 1_024
            if code == .success && completed == cycles && memoryWithinBounds {
                lines[0] = "Mowy P2 proof: SUCCESS"
            } else if code == .success && completed == cycles {
                lines[0] = "Mowy P2 proof: MEMORY_LIMIT"
            } else {
                lines[0] = "Mowy P2 proof: \(String(describing: code).uppercased())"
            }
            lines.append("cycles_completed=\(completed)")
            lines.append("peak_resident_bytes=\(peak)")
            lines.append("peak_growth_bytes=\(peakGrowth)")
            lines.append("final_resident_bytes=\(finalResident)")
            lines.append("final_growth_bytes=\(finalGrowth)")
            lines.append("memory_within_bounds=\(memoryWithinBounds)")
            self.publish(lines.joined(separator: "\n"))
        }
    }

    deinit {
        cancellation.cancel()
    }

    private func requestedCycles() -> Int? {
        let arguments = CommandLine.arguments
        guard let index = arguments.firstIndex(of: "--cycles") else { return 1 }
        let valueIndex = arguments.index(after: index)
        guard valueIndex < arguments.endIndex,
              let value = Int(arguments[valueIndex]),
              (1...10).contains(value) else {
            return nil
        }
        return value
    }

    private func runDevelopmentCommand(
        mode: String,
        cancellation: MowyProofCancellation
    ) -> String {
        let now = UInt64(Date().timeIntervalSince1970)
        switch mode {
        case "resume-relock-probe":
            guard let operationId = argument("--operation") else {
                return "Mowy P2 relock probe: INVALID_INPUT"
            }
            let store = MowyRelockProbeProtectedKeyStore(protectedCheck: 8) { [weak self] in
                self?.publishRelockProbe(
                    [
                        "Mowy P2 relock probe: LOCK_DEVICE_NOW",
                        "mode=resume-relock-probe",
                        "checkpoint_reached=true",
                    ].joined(separator: "\n")
                ) ?? false
            }
            let result = resumeDevelopmentTransfer(
                protectedStore: store,
                cancellation: cancellation,
                now: now,
                receiverOperationId: operationId
            )
            let expectedFailClosed = store.checkpointReached &&
                store.lockObserved &&
                result.code == .unavailable &&
                result.receipt == nil
            return [
                "Mowy P2 relock probe: \(expectedFailClosed ? "SUCCESS" : "FAILED")",
                "mode=resume-relock-probe",
                "checkpoint_reached=\(store.checkpointReached)",
                "lock_observed=\(store.lockObserved)",
                "core_code=\(codeName(result.code))",
                "receipt_present=\(result.receipt != nil)",
                "expected_fail_closed=\(expectedFailClosed)",
            ].joined(separator: "\n")
        case "publish":
            let result = MowyDevelopmentProofRunner.publish(now: now)
            guard result.code == .success, let bundle = result.bundle else {
                return "Mowy P2 development: \(codeName(result.code))"
            }
            return [
                "Mowy P2 development: SUCCESS",
                "mode=publish",
                "bundle=\(MowyDevelopmentProofCodec.encode(bundle))",
            ].joined(separator: "\n")
        case "prepare":
            guard let encoded = argument("--bundle"),
                  let bundle = MowyDevelopmentProofCodec.decodeBundle(encoded),
                  let lengthText = argument("--length"),
                  let length = UInt64(lengthText) else {
                return "Mowy P2 development: INVALID_INPUT"
            }
            let result = MowyDevelopmentProofRunner.prepare(
                cancellation: cancellation,
                now: now,
                plaintextLength: length,
                recipientBundle: bundle
            )
            guard result.code == .success, let transfer = result.transfer else {
                return "Mowy P2 development: \(codeName(result.code))"
            }
            return [
                "Mowy P2 development: SUCCESS",
                "mode=prepare",
                "transfer=\(MowyDevelopmentProofCodec.encode(transfer))",
                "ciphertext_source_path=\(result.ciphertextSourcePath)",
            ].joined(separator: "\n")
        case "stage":
            guard let encodedBundle = argument("--bundle"),
                  let bundle = MowyDevelopmentProofCodec.decodeBundle(encodedBundle),
                  let encodedTransfer = argument("--transfer"),
                  let transfer = MowyDevelopmentProofCodec.decodeTransfer(encodedTransfer) else {
                return "Mowy P2 development: INVALID_INPUT"
            }
            let result = MowyDevelopmentProofRunner.stage(
                now: now,
                senderBundle: bundle,
                transfer: transfer
            )
            guard result.code == .success else {
                return "Mowy P2 development: \(codeName(result.code))"
            }
            return [
                "Mowy P2 development: SUCCESS",
                "mode=stage",
                "receiver_operation_id=\(transfer.receiverOperationId)",
                "ciphertext_destination_path=\(result.ciphertextDestinationPath)",
            ].joined(separator: "\n")
        case "resume":
            guard let operationId = argument("--operation") else {
                return "Mowy P2 development: INVALID_INPUT"
            }
            let result = MowyDevelopmentProofRunner.resume(
                cancellation: cancellation,
                now: now,
                receiverOperationId: operationId
            )
            guard result.code == .success, let receipt = result.receipt else {
                return "Mowy P2 development: \(codeName(result.code))"
            }
            return [
                "Mowy P2 development: SUCCESS",
                "mode=resume",
                "proof_id=\(receipt.proofId)",
                "plaintext_length=\(receipt.plaintextLength)",
                "ciphertext_length=\(receipt.ciphertextLength)",
                "ciphertext_sha256=\(receipt.ciphertextSha256)",
                "archive_sha256=\(receipt.archiveSha256)",
            ].joined(separator: "\n")
        case "cleanup-sender":
            guard let encodedTransfer = argument("--transfer"),
                  let transfer = MowyDevelopmentProofCodec.decodeTransfer(encodedTransfer) else {
                return "Mowy P2 development: INVALID_INPUT"
            }
            let result = MowyDevelopmentProofRunner.cleanupSender(now: now, transfer: transfer)
            return [
                "Mowy P2 development: \(codeName(result.code))",
                "mode=\(mode)",
            ].joined(separator: "\n")
        default:
            return "Mowy P2 development: INVALID_INPUT"
        }
    }

    private func argument(_ name: String) -> String? {
        let arguments = CommandLine.arguments
        guard let index = arguments.firstIndex(of: name) else { return nil }
        let valueIndex = arguments.index(after: index)
        return valueIndex < arguments.endIndex ? arguments[valueIndex] : nil
    }

    private func codeName(_ code: MowyCoreCode) -> String {
        String(describing: code).uppercased()
    }

    private func publish(_ text: String) {
        let resultURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("mowy-p2-proof-result.txt")
        try? text.write(to: resultURL, atomically: true, encoding: .utf8)
        publishToScreen(text)
    }

    // This file contains only the probe verdict and booleans. Keeping that
    // coarse receipt readable while locked lets the harness observe a
    // fail-closed result without weakening protection on any core artifact.
    private func prepareRelockProbeReceipt() -> Bool {
        let fileManager = FileManager.default
        let resultURL = fileManager.temporaryDirectory
            .appendingPathComponent("mowy-p2-relock-result.txt")
        do {
            if fileManager.fileExists(atPath: resultURL.path) {
                try fileManager.removeItem(at: resultURL)
            }
            guard fileManager.createFile(
                atPath: resultURL.path,
                contents: nil,
                attributes: [
                    .posixPermissions: 0o600,
                    .protectionKey: FileProtectionType.none,
                ]
            ) else {
                return false
            }
            try fileManager.setAttributes(
                [
                    .posixPermissions: 0o600,
                    .protectionKey: FileProtectionType.none,
                ],
                ofItemAtPath: resultURL.path
            )
            return true
        } catch {
            try? fileManager.removeItem(at: resultURL)
            return false
        }
    }

    @discardableResult
    private func publishRelockProbe(_ text: String) -> Bool {
        let fileManager = FileManager.default
        let resultURL = fileManager.temporaryDirectory
            .appendingPathComponent("mowy-p2-relock-result.txt")
        guard let data = text.data(using: .utf8),
              fileManager.fileExists(atPath: resultURL.path) else {
            publishToScreen("Mowy P2 relock probe: RECEIPT_WRITE_FAILED")
            return false
        }
        do {
            let handle = try FileHandle(forWritingTo: resultURL)
            defer { try? handle.close() }
            try handle.truncate(atOffset: 0)
            try handle.write(contentsOf: data)
            try handle.synchronize()
        } catch {
            try? fileManager.removeItem(at: resultURL)
            publishToScreen("Mowy P2 relock probe: RECEIPT_WRITE_FAILED")
            return false
        }
        publishToScreen(text)
        return true
    }

    private func publishToScreen(_ text: String) {
        DispatchQueue.main.async { [weak self] in
            self?.resultLabel.text = text
        }
    }
}

// Development-only physical probe. For one freshly staged receiver, callback
// eight follows authenticated decryption and sync but precedes plaintext
// promotion. Holding that boundary lets a real device relock while durable
// receiver state can retry by opaque operation ID; the production adapter and
// ABI stay unchanged.
private final class MowyRelockProbeProtectedKeyStore: NativeProtectedKeyStore, @unchecked Sendable {
    private let store = MowyNativeProtectedKeyStore()
    private let protectedCheck: Int
    private let onCheckpoint: () -> Bool
    private let stateLock = NSLock()
    private var protectedChecks = 0
    private var didReachCheckpoint = false
    private var didObserveLock = false
    private var didExpireBackgroundTask = false

    init(protectedCheck: Int, onCheckpoint: @escaping () -> Bool) {
        self.protectedCheck = protectedCheck
        self.onCheckpoint = onCheckpoint
    }

    var checkpointReached: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return didReachCheckpoint
    }

    var lockObserved: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return didObserveLock
    }

    func protectedDataAvailable() -> NativeBridgeResponse {
        stateLock.lock()
        protectedChecks += 1
        let shouldWait = protectedChecks == protectedCheck
        if shouldWait {
            didReachCheckpoint = true
        }
        stateLock.unlock()

        if shouldWait {
            if waitForPhysicalRelock() {
                return NativeBridgeResponse(
                    code: .success,
                    flag: false,
                    number: 0,
                    keyState: .absent,
                    path: ""
                )
            }
        }
        return store.protectedDataAvailable()
    }

    // Returns true when the probe must force an unavailable result because its
    // evidence checkpoint could not be observed safely.
    private func waitForPhysicalRelock() -> Bool {
        let application = UIApplication.shared
        let backgroundTask = application.beginBackgroundTask(
            withName: "MowyP2RelockProbe"
        ) { [weak self] in
            self?.markBackgroundTaskExpired()
        }
        defer {
            if backgroundTask != .invalid {
                application.endBackgroundTask(backgroundTask)
            }
        }
        guard onCheckpoint(), backgroundTask != .invalid else { return true }

        let deadline = Date().addingTimeInterval(45)
        while Date() < deadline {
            if !application.isProtectedDataAvailable {
                stateLock.lock()
                didObserveLock = true
                stateLock.unlock()
                return false
            }
            stateLock.lock()
            let expired = didExpireBackgroundTask
            stateLock.unlock()
            if expired || application.backgroundTimeRemaining <= 2 {
                return true
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return true
    }

    private func markBackgroundTaskExpired() {
        stateLock.lock()
        didExpireBackgroundTask = true
        stateLock.unlock()
    }

    func keyState() -> NativeBridgeResponse { store.keyState() }
    func installationMarkerExists() -> NativeBridgeResponse { store.installationMarkerExists() }
    func databaseExists() -> NativeBridgeResponse { store.databaseExists() }
    func prepareNamespaces() -> NativeBridgeResponse { store.prepareNamespaces() }
    func commitCompanions() -> NativeBridgeResponse { store.commitCompanions() }

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
        store.storeNew(
            word0: word0,
            word1: word1,
            word2: word2,
            word3: word3,
            word4: word4,
            word5: word5,
            word6: word6,
            word7: word7,
            word8: word8,
            word9: word9,
            word10: word10,
            word11: word11
        )
    }

    func beginLoad() -> NativeBridgeResponse { store.beginLoad() }

    func loadWord(token: UInt64, index: UInt8) -> NativeBridgeResponse {
        store.loadWord(token: token, index: index)
    }

    func finishLoad(token: UInt64) -> NativeBridgeResponse {
        store.finishLoad(token: token)
    }
}

private func currentResidentBytes() -> UInt64 {
    var information = mach_task_basic_info_data_t()
    var count = mach_msg_type_number_t(
        MemoryLayout<mach_task_basic_info_data_t>.size / MemoryLayout<natural_t>.size
    )
    let status = withUnsafeMutablePointer(to: &information) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
        }
    }
    return status == KERN_SUCCESS ? UInt64(information.resident_size) : 0
}

private func peakResidentBytes() -> UInt64 {
    var usage = rusage()
    return getrusage(RUSAGE_SELF, &usage) == 0 ? UInt64(usage.ru_maxrss) : currentResidentBytes()
}
