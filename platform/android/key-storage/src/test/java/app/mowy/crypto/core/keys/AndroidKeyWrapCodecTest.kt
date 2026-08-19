/** Verifies the frozen AES-GCM transform with a host JCE key. */
package app.mowy.crypto.core.keys

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class AndroidKeyWrapCodecTest {
    @Test
    fun roundTripsWithFreshProviderIvAndExactAssociatedData() {
        val key = newKey()
        val material = ByteArray(96) { it.toByte() }

        val first = AndroidKeyWrapCodec.encrypt(material, key)
        val second = AndroidKeyWrapCodec.encrypt(material, key)
        val parsedFirst = requireNotNull(WrappedKeyBlob.decode(first))
        val parsedSecond = requireNotNull(WrappedKeyBlob.decode(second))

        assertArrayEquals(material, AndroidKeyWrapCodec.decrypt(parsedFirst, key))
        assertFalse(parsedFirst.iv.contentEquals(parsedSecond.iv))
        assertArrayEquals(
            "MOWY-P2-KEY-WRAP-V1\u0000".toByteArray(Charsets.US_ASCII),
            AndroidKeyWrapCodec.associatedDataForTest(),
        )
    }

    @Test
    fun rejectsWrongTagAndAssociatedData() {
        val key = newKey()
        val encoded = AndroidKeyWrapCodec.encrypt(ByteArray(96), key)
        val wrongTag = encoded.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
        val parsedWrongTag = requireNotNull(WrappedKeyBlob.decode(wrongTag))
        assertThrows(AEADBadTagException::class.java) {
            AndroidKeyWrapCodec.decrypt(parsedWrongTag, key)
        }

        val parsed = requireNotNull(WrappedKeyBlob.decode(encoded))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, parsed.iv))
        cipher.updateAAD("wrong-associated-data".toByteArray(Charsets.US_ASCII))
        assertThrows(AEADBadTagException::class.java) {
            cipher.doFinal(parsed.ciphertextAndTag)
        }
    }

    private fun newKey(): SecretKey {
        return KeyGenerator.getInstance("AES").run {
            init(256)
            generateKey()
        }
    }
}
