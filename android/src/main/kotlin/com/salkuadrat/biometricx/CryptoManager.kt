package com.salkuadrat.biometricx

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.google.gson.Gson
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

interface CryptoManager {
    /**
     * This will gets or generates an instance of SecretKey, and then initializes Chiper with the key.
     * The secret key uses [ENCRYPT_MODE][Cipher.ENCRYPT_MODE].
     *
     * @return [Cipher]
     */
    fun getInitializedCipherForEncryption(
        keyName: String,
        userAuthenticationRequired: Boolean
    ): Cipher

    /**
     * This will gets or generates an instance of SecretKey, and then initializes Cipher with the key.
     * The secret key uses [DECRYPT_MODE][Cipher.DECRYPT_MODE].
     *
     * @return [Cipher]
     */
    fun getInitializedCipherForDecryption(
        keyName: String,
        initializationVector: ByteArray,
        userAuthenticationRequired: Boolean
    ): Cipher

    /**
     * Cipher created with [getInitializedCipherForEncryption] is used here to encrypt [message].
     *
     * @return [Ciphertext]
     */
    fun encryptData(message: String, cipher: Cipher): Ciphertext

    /**
     * Cipher created with [getInitializedCipherForDecryption] is used here to decrypt [ciphertext].
     *
     * @return [String]
     */
    fun decryptData(ciphertext: ByteArray, cipher: Cipher): String

    /**
     * Save [ciphertext] to Shared Preferences.
     *
     * @param context [Context]
     * @param ciphertext [Ciphertext]
     * @param prefName [String]
     * @param prefMode [Int]
     * @param prefKey [String]
     */
    fun saveCiphertext(
        context: Context,
        ciphertext: Ciphertext,
        prefName: String,
        prefMode: Int,
        prefKey: String
    )

    /**
     * Restored a saved [Ciphertext] from Shared Preferences.
     *
     * @param context [Context]
     * @param prefName [String]
     * @param prefMode [Int]
     * @param prefKey [String]
     *
     * @return [Ciphertext]
     */
    fun restoreCiphertext(
        context: Context,
        prefName: String,
        prefMode: Int,
        prefKey: String
    ): Ciphertext?
}

fun CryptoManager(context: Context): CryptoManager = CryptoManagerImpl(context = context)

data class Ciphertext(val ciphertext: ByteArray, val initializationVector: ByteArray)

private class CryptoManagerImpl(context: Context) : CryptoManager {
    private val context: Context = context

    private val KEY_SIZE = 256
    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
    private val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
    private val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES

    @RequiresApi(Build.VERSION_CODES.M)
    override fun getInitializedCipherForEncryption(
        keyName: String,
        userAuthenticationRequired: Boolean
    ): Cipher {
        val cipher = getCipher()
        val secretKey = getSecretKey(keyName, userAuthenticationRequired)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun getInitializedCipherForDecryption(
        keyName: String,
        initializationVector: ByteArray,
        userAuthenticationRequired: Boolean
    ): Cipher {
        val cipher = getCipher()
        val secretKey = getSecretKey(keyName, userAuthenticationRequired)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
        return cipher
    }

    override fun encryptData(message: String, cipher: Cipher): Ciphertext {
        val messageByte = message.toByteArray(Charset.forName("UTF-8"))
        val ciphertext = cipher.doFinal(messageByte)
        return Ciphertext(ciphertext, cipher.iv)
    }

    override fun decryptData(ciphertext: ByteArray, cipher: Cipher): String {
        val messageByte = cipher.doFinal(ciphertext)
        val message = String(messageByte, Charset.forName("UTF-8"))
        return message
    }

    private fun getCipher(): Cipher {
        return Cipher.getInstance("$ENCRYPTION_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING")
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getSecretKey(keyName: String, userAuthenticationRequired: Boolean): SecretKey {
        // If Secretkey exist for that keyName, grab and return it.
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        keyStore.getKey(keyName, null)?.let { 
            println("Secretkey exist")
            return it as SecretKey 
        }
        println("Secretkey no-exist")
        // If not, generate a new one
        val keyGen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyName,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )
        ) {
            keyGenParameterSpec.setIsStrongBoxBacked(true)
        }

        keyGenParameterSpec.setBlockModes(ENCRYPTION_BLOCK_MODE)
        keyGenParameterSpec.setEncryptionPaddings(ENCRYPTION_PADDING)
        keyGenParameterSpec.setUserAuthenticationRequired(userAuthenticationRequired)
        keyGenParameterSpec.setKeySize(KEY_SIZE)
        keyGenParameterSpec.build()

        keyGen.init(
            keyGenParameterSpec.build()
        )

        return keyGen.generateKey()
    }

    override fun saveCiphertext(
        context: Context,
        ciphertext: Ciphertext,
        prefName: String,
        prefMode: Int,
        prefKey: String
    ) {
        val json = Gson().toJson(ciphertext)
        context.getSharedPreferences(prefName, prefMode).edit().putString(prefKey, json).apply()
    }

    override fun restoreCiphertext(
        context: Context,
        prefName: String,
        prefMode: Int,
        prefKey: String
    ): Ciphertext? {
        val json = context.getSharedPreferences(prefName, prefMode).getString(prefKey, null)
        return Gson().fromJson(json, Ciphertext::class.java)
    }
}
