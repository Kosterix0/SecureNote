package com.example.securenotebook

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.util.Base64
import android.content.SharedPreferences

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button
    private lateinit var showButton: Button

    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var secretKey: SecretKey

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Inicjalizacja widoków
        noteEditText = findViewById(R.id.noteEditText)
        saveButton = findViewById(R.id.saveButton)
        showButton = findViewById(R.id.showButton)

        // Inicjalizacja SharedPreferences
        sharedPreferences = getSharedPreferences("SecureNotebook", MODE_PRIVATE)

        // Generowanie klucza AES
        secretKey = generateSecretKey()

        // Obsługa przycisku "Zapisz notatkę"
        saveButton.setOnClickListener {
            promptForPassword { password ->
                val note = noteEditText.text.toString()
                if (note.isNotEmpty()) {
                    val encryptedNote = encrypt(note, password)
                    sharedPreferences.edit().putString("encryptedNote", encryptedNote).apply()
                    Toast.makeText(this, "Notatka zapisana!", Toast.LENGTH_SHORT).show()
                    noteEditText.text.clear()
                } else {
                    Toast.makeText(this, "Nie można zapisać pustej notatki!", Toast.LENGTH_SHORT).show()
                }
            }
        }

        // Obsługa przycisku "Pokaż notatkę"
        showButton.setOnClickListener {
            promptForPassword { password ->
                val encryptedNote = sharedPreferences.getString("encryptedNote", null)
                if (encryptedNote != null) {
                    try {
                        val decryptedNote = decrypt(encryptedNote, password)
                        noteEditText.setText(decryptedNote)
                    } catch (e: Exception) {
                        Toast.makeText(this, "Nieprawidłowe hasło!", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(this, "Brak zapisanej notatki!", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    // Generowanie klucza AES
    private fun generateSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        return keyGenerator.generateKey()
    }

    // Szyfrowanie notatki
    private fun encrypt(data: String, password: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, password.toByteArray().copyOf(12)) // IV generowane na podstawie hasła
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    // Odszyfrowanie notatki
    private fun decrypt(encryptedData: String, password: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, password.toByteArray().copyOf(12)) // IV generowane na podstawie hasła
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        val encryptedBytes = Base64.decode(encryptedData, Base64.DEFAULT)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }

    // Okno dialogowe do wprowadzenia hasła
    private fun promptForPassword(callback: (String) -> Unit) {
        val passwordInput = EditText(this)
        val dialog = AlertDialog.Builder(this)
            .setTitle("Wprowadź hasło")
            .setView(passwordInput)
            .setPositiveButton("OK") { _, _ ->
                val password = passwordInput.text.toString()
                if (password.isNotEmpty()) {
                    callback(password)
                } else {
                    Toast.makeText(this, "Hasło nie może być puste!", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Anuluj", null)
            .create()
        dialog.show()
    }
}


