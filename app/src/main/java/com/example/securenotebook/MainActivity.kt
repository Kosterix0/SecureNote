package com.example.securenotebook

import android.content.Context
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button

    private lateinit var secretKey: SecretKey
    private lateinit var iv: ByteArray

    private val KEY_ALIAS = "myKeyAlias"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        noteEditText = findViewById(R.id.noteEditText)
        saveButton = findViewById(R.id.saveButton)

        secretKey = getSecretKeyFromKeystore()
        iv = generateIV()

        saveButton.setOnClickListener {
            val note = noteEditText.text.toString()
            if (note.isNotEmpty()) {
                try {
                    val encryptedNote = encrypt(note, secretKey, iv)
                    saveNoteToSharedPreferences(encryptedNote)
                    Toast.makeText(this, "Notatka została zapisana!", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    e.printStackTrace()
                    Toast.makeText(this, "Błąd podczas zapisywania notatki: ${e.message}", Toast.LENGTH_LONG).show()
                }
            } else {
                Toast.makeText(this, "Proszę wpisać notatkę!", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun getSecretKeyFromKeystore(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val existingKey = keyStore.getEntry(KEY_ALIAS, null)
        return if (existingKey == null) {
            val keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
            keyGenerator.generateKey()
        } else {
            (existingKey as KeyStore.SecretKeyEntry).secretKey
        }
    }

    private fun generateIV(): ByteArray {
        val ivBytes = ByteArray(12) // GCM expects 12 bytes for the IV
        val secureRandom = java.security.SecureRandom()
        secureRandom.nextBytes(ivBytes)
        return ivBytes
    }

    private fun encrypt(data: String, secretKey: SecretKey, iv: ByteArray): String {
        val gcmSpec = GCMParameterSpec(128, iv)  // 128-bit authentication tag length
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    private fun saveNoteToSharedPreferences(encryptedNote: String) {
        val sharedPreferences = getSharedPreferences("SecureNotes", Context.MODE_PRIVATE)
        val editor = sharedPreferences.edit()
        editor.putString("encrypted_note", encryptedNote)
        editor.putString("iv", Base64.encodeToString(iv, Base64.DEFAULT)) // Save IV as Base64
        editor.apply()
    }
}
