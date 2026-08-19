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
            DispatchQueue.global(qos: .userInitiated).async { [cancellation] in
                self.publish(self.runDevelopmentCommand(mode: mode, cancellation: cancellation))
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
        DispatchQueue.main.async { [weak self] in
            self?.resultLabel.text = text
        }
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
