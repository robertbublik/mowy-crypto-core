/** Verifies the frozen wrapped-key parser without invoking Android services. */
package app.mowy.crypto.core.keys

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class WrappedKeyBlobTest {
    @Test
    fun roundTripsExactBlob() {
        val iv = ByteArray(12) { it.toByte() }
        val ciphertext = ByteArray(112) { (it + 12).toByte() }

        val parsed = WrappedKeyBlob.decode(WrappedKeyBlob.encode(iv, ciphertext))

        assertNotNull(parsed)
        assertArrayEquals(iv, parsed?.iv)
        assertArrayEquals(ciphertext, parsed?.ciphertextAndTag)
    }

    @Test
    fun rejectsUnknownVersionAndIvLength() {
        val valid = WrappedKeyBlob.encode(ByteArray(12), ByteArray(112))
        assertNull(WrappedKeyBlob.decode(valid.copyOf().also { it[0] = 2 }))
        assertNull(WrappedKeyBlob.decode(valid.copyOf().also { it[1] = 11 }))
    }

    @Test
    fun rejectsTruncationAndTrailingData() {
        val valid = WrappedKeyBlob.encode(ByteArray(12), ByteArray(112))
        assertNull(WrappedKeyBlob.decode(valid.copyOf(valid.size - 1)))
        assertNull(WrappedKeyBlob.decode(valid.copyOf(valid.size + 1)))
    }
}
