package com.example.securenotebook

import android.content.Context
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import android.util.Base64
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button
    private lateinit var showButton: Button

    private lateinit var secretKey: SecretKey

    private val KEY_ALIAS = "myKeyAlias"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        noteEditText = findViewById(R.id.noteEditText)
        saveButton = findViewById(R.id.saveButton)
        showButton = findViewById(R.id.showButton)

        secretKey = getSecretKeyFromKeystore()

        saveButton.setOnClickListener {
            val note = noteEditText.text.toString()
            if (note.isNotEmpty()) {
                val encryptedNote = encrypt(note, secretKey)
                saveNoteToSharedPreferences(encryptedNote)
                Toast.makeText(this, "Notatka została zapisana!", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Proszę wpisać notatkę!", Toast.LENGTH_SHORT).show()
            }
        }

        showButton.setOnClickListener {
            val encryptedNote = loadNoteFromSharedPreferences()
            if (encryptedNote != null) {
                val decryptedNote = decrypt(encryptedNote, secretKey)
                noteEditText.setText(decryptedNote)
                Toast.makeText(this, "Notatka została wyświetlona!", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Brak zapisanej notatki", Toast.LENGTH_SHORT).show()
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

    private fun encrypt(data: String, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        // System Keystore automatycznie generuje IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val encryptedBytes = cipher.doFinal(data.toByteArray())

        // Zapisz wygenerowane IV do SharedPreferences
        val iv = cipher.iv
        saveIvToSharedPreferences(iv)

        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    private fun decrypt(encryptedData: String, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        // Pobierz zapisane IV z SharedPreferences
        val iv = loadIvFromSharedPreferences()
        val gcmSpec = GCMParameterSpec(128, iv) // Używamy IV zapisane wcześniej

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val encryptedBytes = Base64.decode(encryptedData, Base64.DEFAULT)
        val decryptedBytes = cipher.doFinal(encryptedBytes)

        return String(decryptedBytes)
    }

    private fun saveIvToSharedPreferences(iv: ByteArray) {
        val sharedPreferences = getSharedPreferences("SecureNotes", Context.MODE_PRIVATE)
        val editor = sharedPreferences.edit()
        editor.putString("iv", Base64.encodeToString(iv, Base64.DEFAULT)) // Zapisz IV
        editor.apply()
    }

    private fun loadIvFromSharedPreferences(): ByteArray {
        val sharedPreferences = getSharedPreferences("SecureNotes", Context.MODE_PRIVATE)
        val ivBase64 = sharedPreferences.getString("iv", null)
        return Base64.decode(ivBase64, Base64.DEFAULT)
    }

    private fun saveNoteToSharedPreferences(encryptedNote: String) {
        val sharedPreferences = getSharedPreferences("SecureNotes", Context.MODE_PRIVATE)
        val editor = sharedPreferences.edit()
        editor.putString("encrypted_note", encryptedNote)
        editor.apply()
    }

    private fun loadNoteFromSharedPreferences(): String? {
        val sharedPreferences = getSharedPreferences("SecureNotes", Context.MODE_PRIVATE)
        return sharedPreferences.getString("encrypted_note", null)
    }
}

