/** Connects the fixed UniFFI proof facade to Android Keystore and no-backup state. */
package app.mowy.crypto.core.keys

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.system.Os
import android.system.OsConstants
import app.mowy.crypto.core.MowyCancellation
import app.mowy.crypto.core.MowyCoreCode
import app.mowy.crypto.core.MowyProofResult
import app.mowy.crypto.core.NativeBridgeResponse
import app.mowy.crypto.core.NativeProtectedKeyState
import app.mowy.crypto.core.NativeProtectedKeyStore
import app.mowy.crypto.core.runDevelopmentProof
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption

class MowyProofCancellation : MowyCancellation {
    @Volatile
    private var cancelled = false

    fun cancel() {
        cancelled = true
    }

    override fun isCancelled(): NativeBridgeResponse = success(flag = cancelled)
}

object MowyProofRunner {
    fun run(
        context: Context,
        cancellation: MowyProofCancellation,
        now: ULong,
        plaintextLength: ULong,
    ): MowyProofResult = runDevelopmentProof(
        MowyNativeProtectedKeyStore(context.applicationContext),
        cancellation,
        now,
        plaintextLength,
    )
}

@SuppressLint("NewApi") // The semantic entry returns unavailable before API-28 state is touched.
@TargetApi(Build.VERSION_CODES.P)
internal class MowyNativeProtectedKeyStore(private val context: Context) : NativeProtectedKeyStore {
    private val keyStore = MowyProtectedKeyStore(context)
    private val keyguard = context.getSystemService(KeyguardManager::class.java)
    private val loadLock = Any()
    private var activeToken: ULong? = null
    private var activeMaterial: ByteArray? = null
    private var nextToken = 1UL

    override fun protectedDataAvailable(): NativeBridgeResponse =
        success(flag = isProtectedDataAvailable())

    override fun keyState(): NativeBridgeResponse = response {
        val state = keyStore.state()
        success(
            keyState = when (state) {
                MowyProtectedKeyState.ABSENT -> NativeProtectedKeyState.ABSENT
                MowyProtectedKeyState.PRESENT -> NativeProtectedKeyState.PRESENT
                MowyProtectedKeyState.PARTIAL -> NativeProtectedKeyState.PARTIAL
            },
        )
    }

    override fun installationMarkerExists(): NativeBridgeResponse = response {
        success(flag = isRegularFile(File(proofRoot(), INSTALLATION_MARKER)))
    }

    override fun databaseExists(): NativeBridgeResponse = response {
        success(flag = isRegularFile(File(proofRoot(), DATABASE_NAME)))
    }

    override fun prepareNamespaces(): NativeBridgeResponse = response {
        requireProtectedData()
        val packageDirectory = File(context.noBackupFilesDir, PACKAGE_DIRECTORY)
        ensurePrivateDirectory(packageDirectory)
        val root = File(packageDirectory, PROOF_DIRECTORY)
        ensurePrivateDirectory(root)
        DIRECTORY_NAMES.forEach { name -> ensurePrivateDirectory(File(root, name)) }
        requireProtectedData()
        success(path = root.canonicalPath)
    }

    override fun commitCompanions(): NativeBridgeResponse = response {
        requireProtectedData()
        val root = proofRoot()
        val marker = File(root, INSTALLATION_MARKER)
        val database = File(root, DATABASE_NAME)
        val markerExists = isRegularFile(marker)
        val databaseExists = isRegularFile(database)
        if (markerExists && databaseExists) {
            return@response success()
        }
        if (markerExists || databaseExists) {
            throw MowyProofPlatformException(MowyCoreCode.UNAVAILABLE)
        }
        createPrivateFile(marker)
        createPrivateFile(database)
        requireProtectedData()
        success()
    }

    override fun storeNew(
        word0: ULong,
        word1: ULong,
        word2: ULong,
        word3: ULong,
        word4: ULong,
        word5: ULong,
        word6: ULong,
        word7: ULong,
        word8: ULong,
        word9: ULong,
        word10: ULong,
        word11: ULong,
    ): NativeBridgeResponse = response {
        val words = longArrayOf(
            word0.toLong(), word1.toLong(), word2.toLong(), word3.toLong(),
            word4.toLong(), word5.toLong(), word6.toLong(), word7.toLong(),
            word8.toLong(), word9.toLong(), word10.toLong(), word11.toLong(),
        )
        val material = ByteArray(ROOT_KEY_MATERIAL_BYTES)
        try {
            words.forEachIndexed { index, signedWord ->
                val word = signedWord.toULong()
                for (offset in 0 until WORD_BYTES) {
                    val shift = (WORD_BYTES - 1 - offset) * Byte.SIZE_BITS
                    material[index * WORD_BYTES + offset] =
                        ((word shr shift) and 0xffUL).toByte()
                }
            }
            keyStore.storeNew(material)
            success()
        } finally {
            words.fill(0L)
            material.fill(0)
        }
    }

    override fun beginLoad(): NativeBridgeResponse = response {
        requireProtectedData()
        synchronized(loadLock) {
            if (activeToken != null || activeMaterial != null) {
                throw MowyProofPlatformException(MowyCoreCode.CONFLICT)
            }
            val material = keyStore.load()
            if (material.size != ROOT_KEY_MATERIAL_BYTES) {
                material.fill(0)
                throw MowyProofPlatformException(MowyCoreCode.UNAVAILABLE)
            }
            val token = nextToken
            nextToken = if (nextToken == ULong.MAX_VALUE) 1UL else nextToken + 1UL
            activeToken = token
            activeMaterial = material
            success(number = token)
        }
    }

    override fun loadWord(token: ULong, index: UByte): NativeBridgeResponse = response {
        synchronized(loadLock) {
            val material = activeMaterial
            if (activeToken != token || material == null || index.toInt() >= ROOT_WORDS) {
                throw MowyProofPlatformException(MowyCoreCode.INVALID_INPUT)
            }
            val start = index.toInt() * WORD_BYTES
            var word = 0UL
            for (offset in 0 until WORD_BYTES) {
                word = (word shl Byte.SIZE_BITS) or material[start + offset].toUByte().toULong()
            }
            success(number = word)
        }
    }

    override fun finishLoad(token: ULong): NativeBridgeResponse = response {
        synchronized(loadLock) {
            if (activeToken != token || activeMaterial == null) {
                throw MowyProofPlatformException(MowyCoreCode.CONFLICT)
            }
            activeMaterial?.fill(0)
            activeMaterial = null
            activeToken = null
            success()
        }
    }

    private fun proofRoot(): File = File(
        File(context.noBackupFilesDir, PACKAGE_DIRECTORY),
        PROOF_DIRECTORY,
    )

    private fun ensurePrivateDirectory(directory: File) {
        requireProtectedData()
        val path = directory.toPath()
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                throw MowyProofPlatformException(MowyCoreCode.UNAVAILABLE)
            }
        } else if (!directory.mkdir()) {
            throw MowyProofPlatformException(MowyCoreCode.STORAGE)
        }
        val noBackupRoot = context.noBackupFilesDir.canonicalFile.path + File.separator
        if (!directory.canonicalFile.path.startsWith(noBackupRoot)) {
            throw MowyProofPlatformException(MowyCoreCode.UNAVAILABLE)
        }
        Os.chmod(directory.path, DIRECTORY_MODE)
    }

    private fun createPrivateFile(file: File) {
        if (Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            throw MowyProofPlatformException(MowyCoreCode.CONFLICT)
        }
        FileOutputStream(file, false).use { output -> output.fd.sync() }
        Os.chmod(file.path, FILE_MODE)
        syncDirectory(file.parentFile ?: throw MowyProofPlatformException(MowyCoreCode.STORAGE))
    }

    private fun isRegularFile(file: File): Boolean {
        val path = file.toPath()
        return Files.exists(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
    }

    private fun syncDirectory(directory: File) {
        val descriptor = Os.open(directory.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }

    private fun requireProtectedData() {
        if (!isProtectedDataAvailable()) {
            throw MowyProofPlatformException(MowyCoreCode.UNAVAILABLE)
        }
    }

    private fun isProtectedDataAvailable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && keyguard?.isDeviceLocked == false

    private inline fun response(operation: () -> NativeBridgeResponse): NativeBridgeResponse =
        try {
            operation()
        } catch (error: MowyKeyStoreException) {
            when (error.code) {
                MowyKeyStoreCode.UNAVAILABLE,
                MowyKeyStoreCode.CORRUPT_STATE,
                -> failure(MowyCoreCode.UNAVAILABLE)
                MowyKeyStoreCode.CONFLICT -> failure(MowyCoreCode.CONFLICT)
                MowyKeyStoreCode.STORAGE -> failure(MowyCoreCode.STORAGE)
            }
        } catch (error: MowyProofPlatformException) {
            failure(error.code)
        } catch (_: Exception) {
            failure(MowyCoreCode.STORAGE)
        }

    private companion object {
        const val ROOT_KEY_MATERIAL_BYTES = 96
        const val ROOT_WORDS = 12
        const val WORD_BYTES = 8
        const val PACKAGE_DIRECTORY = "mowy-p2"
        const val PROOF_DIRECTORY = "proof-v1"
        const val INSTALLATION_MARKER = "installation.v1"
        const val DATABASE_NAME = "operations.sqlite3"
        const val DIRECTORY_MODE = 0b111000000
        const val FILE_MODE = 0b110000000
        val DIRECTORY_NAMES = listOf("source", "ciphertext", "receive-temp", "verified", "archive")
    }
}

private class MowyProofPlatformException(val code: MowyCoreCode) : Exception()

private fun success(
    flag: Boolean = false,
    number: ULong = 0UL,
    keyState: NativeProtectedKeyState = NativeProtectedKeyState.ABSENT,
    path: String = "",
): NativeBridgeResponse = NativeBridgeResponse(
    MowyCoreCode.SUCCESS,
    flag,
    number,
    keyState,
    path,
)

private fun failure(code: MowyCoreCode): NativeBridgeResponse = NativeBridgeResponse(
    code,
    false,
    0UL,
    NativeProtectedKeyState.ABSENT,
    "",
)
