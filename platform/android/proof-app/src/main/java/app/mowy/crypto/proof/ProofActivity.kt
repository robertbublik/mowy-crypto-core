/** Runs only the deterministic public P2 fixture and renders a coarse result. */
package app.mowy.crypto.proof

import android.app.Activity
import android.os.Bundle
import android.os.Debug
import android.system.Os
import android.widget.TextView
import app.mowy.crypto.core.MowyCoreCode
import app.mowy.crypto.core.keys.MowyProofCancellation
import app.mowy.crypto.core.keys.MowyProofRunner
import java.io.File

class ProofActivity : Activity() {
    private val cancellation = MowyProofCancellation()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val resultView = TextView(this).apply {
            text = "Mowy P2 proof: running"
            textSize = 18f
            setPadding(32, 64, 32, 32)
        }
        setContentView(resultView)

        val cycles = requestedCycles()
        if (cycles == null) {
            publishResult(resultView, "Mowy P2 proof: INVALID_INPUT")
            return
        }
        Thread {
            val warmup = MowyProofRunner.run(
                this,
                cancellation,
                (System.currentTimeMillis() / 1_000L).toULong(),
                MAXIMUM_FIXTURE_BYTES,
            )
            if (warmup.code != MowyCoreCode.SUCCESS || warmup.receipt == null) {
                publishResult(resultView, "Mowy P2 proof: ${warmup.code.name}\nwarmup_completed=false")
                return@Thread
            }
            Runtime.getRuntime().gc()
            val baseline = currentResidentBytes()
            val lines = mutableListOf(
                "Mowy P2 proof: running",
                "warmup_completed=true",
                "cycles_requested=$cycles",
                "baseline_resident_bytes=$baseline",
            )
            var completed = 0
            var code = MowyCoreCode.SUCCESS
            for (cycle in 1..cycles) {
                val result = MowyProofRunner.run(
                    this,
                    cancellation,
                    (System.currentTimeMillis() / 1_000L).toULong(),
                    MAXIMUM_FIXTURE_BYTES,
                )
                code = result.code
                val receipt = result.receipt
                if (code != MowyCoreCode.SUCCESS || receipt == null) {
                    break
                }
                completed += 1
                Runtime.getRuntime().gc()
                val resident = currentResidentBytes()
                lines += "cycle_${cycle}_id=${receipt.proofId}"
                lines += "cycle_${cycle}_plaintext=${receipt.plaintextLength}"
                lines += "cycle_${cycle}_ciphertext=${receipt.ciphertextLength}"
                lines += "cycle_${cycle}_ciphertext_sha256=${receipt.ciphertextSha256}"
                lines += "cycle_${cycle}_archive_sha256=${receipt.archiveSha256}"
                lines += "cycle_${cycle}_resident_bytes=$resident"
            }
            val peak = peakResidentBytes()
            val finalResident = currentResidentBytes()
            val peakGrowth = peak.saturatingSubtract(baseline)
            val finalGrowth = finalResident.saturatingSubtract(baseline)
            val memoryWithinBounds = peakGrowth <= MAXIMUM_PEAK_GROWTH_BYTES &&
                finalGrowth <= MAXIMUM_FINAL_GROWTH_BYTES
            lines[0] = if (
                code == MowyCoreCode.SUCCESS && completed == cycles && memoryWithinBounds
            ) {
                "Mowy P2 proof: SUCCESS"
            } else if (code == MowyCoreCode.SUCCESS && completed == cycles) {
                "Mowy P2 proof: MEMORY_LIMIT"
            } else {
                "Mowy P2 proof: ${code.name}"
            }
            lines += "cycles_completed=$completed"
            lines += "peak_resident_bytes=$peak"
            lines += "peak_growth_bytes=$peakGrowth"
            lines += "final_resident_bytes=$finalResident"
            lines += "final_growth_bytes=$finalGrowth"
            lines += "memory_within_bounds=$memoryWithinBounds"
            publishResult(resultView, lines.joinToString("\n"))
        }.start()
    }

    override fun onDestroy() {
        cancellation.cancel()
        super.onDestroy()
    }

    private fun requestedCycles(): Int? {
        if (!intent.hasExtra(CYCLES_EXTRA)) {
            return 1
        }
        return intent.getIntExtra(CYCLES_EXTRA, 0).takeIf { it in 1..MAXIMUM_CYCLES }
    }

    private fun publishResult(resultView: TextView, text: String) {
        val resultFile = File(cacheDir, RESULT_FILE)
        resultFile.writeText(text, Charsets.UTF_8)
        Os.chmod(resultFile.path, FILE_MODE)
        runOnUiThread { resultView.text = text }
    }

    private fun currentResidentBytes(): Long {
        val memory = Debug.MemoryInfo()
        Debug.getMemoryInfo(memory)
        return memory.totalPss.toLong() * KIBIBYTE
    }

    private fun peakResidentBytes(): Long = File("/proc/self/status").useLines { lines ->
        lines.firstOrNull { it.startsWith("VmHWM:") }
            ?.split(Regex("\\s+"))
            ?.getOrNull(1)
            ?.toLongOrNull()
            ?.times(KIBIBYTE)
            ?: currentResidentBytes()
    }

    private fun Long.saturatingSubtract(other: Long): Long = (this - other).coerceAtLeast(0)

    private companion object {
        const val MAXIMUM_FIXTURE_BYTES = 26_214_400UL
        const val MAXIMUM_CYCLES = 10
        const val CYCLES_EXTRA = "cycles"
        const val RESULT_FILE = "mowy-p2-proof-result.txt"
        const val FILE_MODE = 0b110000000
        const val KIBIBYTE = 1_024L
        const val MEBIBYTE = 1_024L * KIBIBYTE
        const val MAXIMUM_PEAK_GROWTH_BYTES = 100L * MEBIBYTE
        const val MAXIMUM_FINAL_GROWTH_BYTES = 20L * MEBIBYTE
    }
}
