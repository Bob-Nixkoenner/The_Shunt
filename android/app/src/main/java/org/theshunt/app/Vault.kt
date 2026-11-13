package org.theshunt.app

import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Seals the secret part of a tunnel (its file with the private and preshared keys,
 * OpenVPN keys, user and password, Tor bridges) with AES-256-GCM before it is
 * written to settings.json. The AES key lives in the Android Keystore (StrongBox
 * when the phone has one, else the TEE) and never leaves it: a copy of the app's
 * files (a backup, a rooted phone's file dump, another device) holds only
 * ciphertext that nobody can open without this phone's key store.
 *
 * Format of a sealed value: "v1:" + Base64(12-byte IV + ciphertext + 16-byte tag).
 * [open] returns null when the value cannot be opened (no key on this device,
 * a different key, damaged data): the tunnel stays locked, nothing crashes.
 *
 * The key provider is a parameter so the JVM tests can use a software key;
 * the app uses [Vault.keystore].
 */
class Vault(private val key: (create: Boolean) -> SecretKey?) {
    // Keystore operations are slow (StrongBox: tens of milliseconds each) and
    // settings.json is read by the UI and the VPN service again and again:
    // what was sealed or opened in this process is kept, both ways.
    private val opened = LinkedHashMap<String, String>()
    private val sealed = LinkedHashMap<String, String>()

    /** Seals [plain]; throws when the key store cannot (then nothing is written in clear). */
    @Synchronized
    fun seal(plain: String): String {
        sealed[plain]?.let { return it }
        val k = key(true) ?: throw IllegalStateException("no key in the key store")
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.ENCRYPT_MODE, k) // the key store picks a fresh random IV
        c.updateAAD(AAD)
        val iv = c.iv
        require(iv.size == IV_BYTES) { "unexpected IV size ${iv.size}" }
        val out = PREFIX + Base64.getEncoder().encodeToString(iv + c.doFinal(plain.toByteArray(Charsets.UTF_8)))
        remember(plain, out)
        return out
    }

    /** Opens a value made by [seal]; null when it cannot be opened on this device. */
    @Synchronized
    fun open(value: String): String? {
        opened[value]?.let { return it }
        if (!value.startsWith(PREFIX)) return null
        return try {
            val raw = Base64.getDecoder().decode(value.substring(PREFIX.length))
            if (raw.size < IV_BYTES + TAG_BITS / 8) return null
            val k = key(false) ?: return null
            val c = Cipher.getInstance(TRANSFORMATION)
            c.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(TAG_BITS, raw, 0, IV_BYTES))
            c.updateAAD(AAD)
            val plain = String(c.doFinal(raw, IV_BYTES, raw.size - IV_BYTES), Charsets.UTF_8)
            remember(plain, value)
            plain
        } catch (e: Exception) {
            null // wrong key, damaged data, key store not ready: locked
        }
    }

    private fun remember(plain: String, value: String) {
        if (opened.size >= CACHE) { opened.clear(); sealed.clear() }
        opened[value] = plain
        sealed[plain] = value
    }

    companion object {
        const val PREFIX = "v1:"
        const val ALIAS = "shunt-tunnel-secrets-v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
        private const val CACHE = 256
        /** Binds a sealed value to its purpose: a tunnel secret of this app. */
        private val AAD = "org.theshunt.app/tunnel-secret/v1".toByteArray()

        fun isSealed(value: String) = value.startsWith(PREFIX)

        /** The app's vault: the key in AndroidKeyStore, made on first use. */
        val keystore: Vault by lazy { androidKeystore() }

        /** A vault on the AndroidKeyStore key with its own (empty) cache; tests use it to read as a new process would. */
        fun androidKeystore() = Vault(::keystoreKey)

        /** Removes the key (tests: a phone without it, as after moving the files to another one). */
        fun deleteKeystoreKey() {
            KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(ALIAS)
        }

        /** Whether the key is in StrongBox / secure hardware (for the instrumented test's log); null when there is none. */
        fun keystoreKeyInfo(): android.security.keystore.KeyInfo? = runCatching {
            val k = KeyStore.getInstance(PROVIDER).apply { load(null) }.getKey(ALIAS, null) as SecretKey
            javax.crypto.SecretKeyFactory.getInstance(k.algorithm, PROVIDER).getKeySpec(k, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
        }.getOrNull()

        private const val PROVIDER = "AndroidKeyStore"

        @Synchronized
        private fun keystoreKey(create: Boolean): SecretKey? {
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
            if (!create) return null
            // StrongBox first (own secure chip), the TEE when there is none
            return try {
                generate(strongBox = true)
            } catch (e: Exception) {
                android.util.Log.i("Shunt", "vault: no StrongBox (${e.javaClass.simpleName}), key in the TEE")
                generate(strongBox = false)
            }
        }

        private fun generate(strongBox: Boolean): SecretKey {
            // Not bound to the screen lock or to user authentication: the VPN must be
            // able to restart (always-on, watchdog) while the phone is locked.
            val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                ALIAS,
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
            return KeyGenerator.getInstance(android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
                .apply { init(spec) }.generateKey()
        }
    }
}
