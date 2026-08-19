/**
 * Protects P2 root key material with the Android Keystore and persists only
 * the exact versioned AES-GCM blob in the app's no-backup namespace.
 */
package app.mowy.crypto.core.keys

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal enum class MowyKeyStoreCode {
    UNAVAILABLE,
    CORRUPT_STATE,
    CONFLICT,
    STORAGE,
}

internal class MowyKeyStoreException(val code: MowyKeyStoreCode) : Exception(code.name)

internal enum class MowyProtectedKeyState {
    ABSENT,
    PRESENT,
    PARTIAL,
}

internal enum class MowyInitializationState {
    EMPTY,
    READY,
    UNAVAILABLE,
}

@SuppressLint("UseRequiresApi") // Internal: the API-24 façade performs the propagated check.
@TargetApi(Build.VERSION_CODES.P)
internal class MowyProtectedKeyStoreApi28(private val context: Context) {
    private val keyguard = context.getSystemService(KeyguardManager::class.java)
    private val keyStore: KeyStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    }
    private val packageDirectory = File(context.noBackupFilesDir, "mowy-p2")
    private val keyDirectory = File(packageDirectory, "keys")
    private val keyFile = File(keyDirectory, "root-key-material.v1")
    private val temporaryFile = File(keyDirectory, ".root-key-material.tmp")

    fun state(): MowyProtectedKeyState = synchronized(PROCESS_LOCK) {
        stateLocked()
    }

    private fun stateLocked(): MowyProtectedKeyState {
        try {
            requireAvailable()
            val aliasExists = keyStore.containsAlias(KEY_ALIAS)
            val blobEntryExists = Files.exists(keyFile.toPath(), LinkOption.NOFOLLOW_LINKS)
            val validBlob = Files.isRegularFile(keyFile.toPath(), LinkOption.NOFOLLOW_LINKS)
            requireAvailable()
            return when {
                !aliasExists && !blobEntryExists -> MowyProtectedKeyState.ABSENT
                aliasExists && validBlob -> MowyProtectedKeyState.PRESENT
                else -> MowyProtectedKeyState.PARTIAL
            }
        } catch (error: MowyKeyStoreException) {
            throw error
        } catch (error: ProviderException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: Exception) {
            throw MowyKeyStoreException(MowyKeyStoreCode.STORAGE)
        }
    }

    fun classifyInitialization(
        markerExists: Boolean,
        databaseExists: Boolean,
    ): MowyInitializationState = synchronized(PROCESS_LOCK) {
        val keyState = stateLocked()
        when {
            keyState == MowyProtectedKeyState.ABSENT && !markerExists && !databaseExists -> {
                MowyInitializationState.EMPTY
            }
            keyState == MowyProtectedKeyState.PRESENT && markerExists && databaseExists -> {
                MowyInitializationState.READY
            }
            else -> MowyInitializationState.UNAVAILABLE
        }
    }

    fun storeNew(material: ByteArray) = synchronized(PROCESS_LOCK) {
        requireAvailable()
        if (material.size != WrappedKeyBlob.ROOT_KEY_MATERIAL_BYTES) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }
        if (stateLocked() != MowyProtectedKeyState.ABSENT) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CONFLICT)
        }

        try {
            val wrappingKey = createWrappingKey()
            val encoded = AndroidKeyWrapCodec.encrypt(material, wrappingKey)
            requireAvailable()
            writeAtomically(encoded, replace = false)
            requireAvailable()
        } catch (error: MowyKeyStoreException) {
            rollbackNewState()
            throw error
        } catch (error: StrongBoxUnavailableException) {
            rollbackNewState()
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: InvalidKeyException) {
            rollbackNewState()
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: ProviderException) {
            rollbackNewState()
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: Exception) {
            rollbackNewState()
            throw MowyKeyStoreException(MowyKeyStoreCode.STORAGE)
        }
    }

    fun load(): ByteArray = synchronized(PROCESS_LOCK) {
        loadLocked()
    }

    private fun loadLocked(): ByteArray {
        requireAvailable()
        if (stateLocked() != MowyProtectedKeyState.PRESENT) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        }

        val parsed = WrappedKeyBlob.decode(readBlob())
            ?: throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        val wrappingKey = try {
            loadWrappingKey()
        } catch (error: UnrecoverableKeyException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: ProviderException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: MowyKeyStoreException) {
            throw error
        } catch (error: Exception) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }
        val plaintext = try {
            AndroidKeyWrapCodec.decrypt(parsed, wrappingKey)
        } catch (error: AEADBadTagException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        } catch (error: UnrecoverableKeyException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: InvalidKeyException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: ProviderException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: Exception) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }

        if (plaintext.size != WrappedKeyBlob.ROOT_KEY_MATERIAL_BYTES) {
            plaintext.fill(0)
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }
        if (!protectedDataAvailable()) {
            plaintext.fill(0)
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        }
        return plaintext
    }

    fun rewrap() = synchronized(PROCESS_LOCK) {
        val material = loadLocked()
        try {
            requireAvailable()
            val encoded = AndroidKeyWrapCodec.encrypt(material, loadWrappingKey())
            requireAvailable()
            writeAtomically(encoded, replace = true)
            requireAvailable()
        } catch (error: MowyKeyStoreException) {
            throw error
        } catch (error: UnrecoverableKeyException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: InvalidKeyException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: ProviderException) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        } catch (error: Exception) {
            throw MowyKeyStoreException(MowyKeyStoreCode.STORAGE)
        } finally {
            material.fill(0)
        }
    }

    private fun createWrappingKey(): SecretKey {
        try {
            return generateWrappingKey(strongBox = true)
        } catch (error: StrongBoxUnavailableException) {
            if (keyStore.containsAlias(KEY_ALIAS)) {
                return loadWrappingKey()
            }
        }
        return generateWrappingKey(strongBox = false)
    }

    private fun generateWrappingKey(strongBox: Boolean): SecretKey {
        val specification = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUnlockedDeviceRequired(true)
            .setUserAuthenticationRequired(false)
            .setRandomizedEncryptionRequired(true)
            .apply {
                if (strongBox) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER).run {
            init(specification)
            generateKey()
        }
    }

    private fun loadWrappingKey(): SecretKey {
        val key = keyStore.getKey(KEY_ALIAS, null)
            ?: throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        return key as? SecretKey
            ?: throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
    }

    private fun readBlob(): ByteArray {
        return try {
            val path = keyFile.toPath()
            if (
                Files.isSymbolicLink(path) ||
                    !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                    Files.size(path) != WrappedKeyBlob.TOTAL_BYTES.toLong()
            ) {
                throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
            }
            Files.readAllBytes(path).also { encoded ->
                if (encoded.size != WrappedKeyBlob.TOTAL_BYTES) {
                    throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
                }
            }
        } catch (error: MowyKeyStoreException) {
            throw error
        } catch (error: Exception) {
            throw MowyKeyStoreException(MowyKeyStoreCode.STORAGE)
        }
    }

    private fun writeAtomically(encoded: ByteArray, replace: Boolean) {
        ensurePrivateDirectory()
        if (Files.isSymbolicLink(temporaryFile.toPath()) || Files.isSymbolicLink(keyFile.toPath())) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }
        if (!replace && keyFile.exists()) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CONFLICT)
        }

        FileOutputStream(temporaryFile, false).use { output ->
            output.write(encoded)
            output.fd.sync()
        }
        Os.chmod(temporaryFile.path, 0b110000000)
        val options = if (replace) {
            arrayOf(StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } else {
            arrayOf(StandardCopyOption.ATOMIC_MOVE)
        }
        Files.move(temporaryFile.toPath(), keyFile.toPath(), *options)
        syncDirectory(keyDirectory)
    }

    private fun ensurePrivateDirectory() {
        val noBackupRoot = context.noBackupFilesDir.canonicalFile
        if (!Files.exists(packageDirectory.toPath(), LinkOption.NOFOLLOW_LINKS) &&
            !packageDirectory.mkdir()
        ) {
            throw MowyKeyStoreException(MowyKeyStoreCode.STORAGE)
        }
        if (
            Files.isSymbolicLink(packageDirectory.toPath()) ||
                !Files.isDirectory(packageDirectory.toPath(), LinkOption.NOFOLLOW_LINKS)
        ) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }
        if (!Files.exists(keyDirectory.toPath(), LinkOption.NOFOLLOW_LINKS) &&
            !keyDirectory.mkdir()
        ) {
            throw MowyKeyStoreException(MowyKeyStoreCode.STORAGE)
        }
        if (
            Files.isSymbolicLink(keyDirectory.toPath()) ||
                !Files.isDirectory(keyDirectory.toPath(), LinkOption.NOFOLLOW_LINKS)
        ) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }
        val canonicalDirectory = keyDirectory.canonicalFile
        if (!canonicalDirectory.path.startsWith(noBackupRoot.path + File.separator)) {
            throw MowyKeyStoreException(MowyKeyStoreCode.CORRUPT_STATE)
        }
        Os.chmod(packageDirectory.path, 0b111000000)
        Os.chmod(keyDirectory.path, 0b111000000)
    }

    private fun syncDirectory(directory: File) {
        val descriptor = Os.open(directory.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }

    private fun rollbackNewState() {
        temporaryFile.delete()
        keyFile.delete()
        runCatching { keyStore.deleteEntry(KEY_ALIAS) }
    }

    private fun requireAvailable() {
        if (!protectedDataAvailable()) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        }
    }

    private fun protectedDataAvailable(): Boolean {
        return keyguard?.isDeviceLocked == false
    }

    private companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val KEY_ALIAS = "app.mowy.prototype.p2.key-wrap.v1"
        val PROCESS_LOCK = Any()
    }
}
