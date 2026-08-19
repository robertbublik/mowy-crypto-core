/**
 * Owns the frozen Android wrapped-key bytes without performing cryptography.
 * Parsing rejects every alternate version, length, and trailing byte.
 */
package app.mowy.crypto.core.keys

internal object WrappedKeyBlob {
    const val ROOT_KEY_MATERIAL_BYTES = 96
    const val IV_BYTES = 12
    const val TAG_BYTES = 16
    private const val VERSION: Byte = 1
    const val TOTAL_BYTES = 2 + IV_BYTES + ROOT_KEY_MATERIAL_BYTES + TAG_BYTES

    data class Parsed(val iv: ByteArray, val ciphertextAndTag: ByteArray)

    fun encode(iv: ByteArray, ciphertextAndTag: ByteArray): ByteArray {
        require(iv.size == IV_BYTES)
        require(ciphertextAndTag.size == ROOT_KEY_MATERIAL_BYTES + TAG_BYTES)
        return ByteArray(TOTAL_BYTES).also { encoded ->
            encoded[0] = VERSION
            encoded[1] = IV_BYTES.toByte()
            iv.copyInto(encoded, destinationOffset = 2)
            ciphertextAndTag.copyInto(encoded, destinationOffset = 2 + IV_BYTES)
        }
    }

    fun decode(encoded: ByteArray): Parsed? {
        if (encoded.size != TOTAL_BYTES || encoded[0] != VERSION || encoded[1] != IV_BYTES.toByte()) {
            return null
        }
        return Parsed(
            iv = encoded.copyOfRange(2, 2 + IV_BYTES),
            ciphertextAndTag = encoded.copyOfRange(2 + IV_BYTES, TOTAL_BYTES),
        )
    }
}
