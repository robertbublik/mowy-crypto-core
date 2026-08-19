/**
 * Performs the exact AES-GCM transform while leaving key ownership to the
 * Android Keystore. Encryption deliberately supplies no IV.
 */
package app.mowy.crypto.core.keys

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object AndroidKeyWrapCodec {
    private const val CIPHER = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128
    private val associatedData = "MOWY-P2-KEY-WRAP-V1\u0000".toByteArray(Charsets.US_ASCII)

    fun encrypt(material: ByteArray, wrappingKey: SecretKey): ByteArray {
        require(material.size == WrappedKeyBlob.ROOT_KEY_MATERIAL_BYTES)
        val cipher = Cipher.getInstance(CIPHER)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey)
        cipher.updateAAD(associatedData)
        val ciphertextAndTag = cipher.doFinal(material)
        val iv = cipher.iv
        require(iv.size == WrappedKeyBlob.IV_BYTES)
        return WrappedKeyBlob.encode(iv, ciphertextAndTag)
    }

    fun decrypt(parsed: WrappedKeyBlob.Parsed, wrappingKey: SecretKey): ByteArray {
        return Cipher.getInstance(CIPHER).run {
            init(Cipher.DECRYPT_MODE, wrappingKey, GCMParameterSpec(TAG_BITS, parsed.iv))
            updateAAD(associatedData)
            doFinal(parsed.ciphertextAndTag)
        }
    }

    fun associatedDataForTest(): ByteArray = associatedData.copyOf()
}
