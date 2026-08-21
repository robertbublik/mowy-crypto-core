/**
 * Keeps the application installable on API 24 while loading the API-28
 * implementation only after the platform and lock checks pass.
 */
package app.mowy.crypto.core.keys

import android.app.KeyguardManager
import android.content.Context
import android.os.Build

internal class MowyProtectedKeyStore(private val context: Context) {
    private val keyguard = context.getSystemService(KeyguardManager::class.java)

    fun state(): MowyProtectedKeyState = synchronized(PROCESS_LOCK) {
        api28().state()
    }

    fun classifyInitialization(
        markerExists: Boolean,
        databaseExists: Boolean,
    ): MowyInitializationState = synchronized(PROCESS_LOCK) {
        api28().classifyInitialization(markerExists, databaseExists)
    }

    fun storeNew(material: ByteArray) = synchronized(PROCESS_LOCK) {
        api28().storeNew(material)
    }

    fun load(): ByteArray = synchronized(PROCESS_LOCK) {
        api28().load()
    }

    fun rewrap() = synchronized(PROCESS_LOCK) {
        api28().rewrap()
    }

    private fun api28(): MowyProtectedKeyStoreApi28 {
        if (!protectedDataAvailable()) {
            throw MowyKeyStoreException(MowyKeyStoreCode.UNAVAILABLE)
        }
        return MowyProtectedKeyStoreApi28(context)
    }

    private fun protectedDataAvailable(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && keyguard?.isDeviceLocked == false
    }

    private companion object {
        val PROCESS_LOCK = Any()
    }
}
