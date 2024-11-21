package com.example.securenotebook

import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button
    private lateinit var showButton: Button
    private lateinit var secretKey: SecretKey

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Inicjalizacja widoków
        noteEditText = findViewById(R.id.noteEditText)
        saveButton = findViewById(R.id.saveButton)
        showButton = findViewById(R.id.showButton)

        // Utworzenie klucza głównego dla EncryptedSharedPreferences
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

// Tworzenie EncryptedSharedPreferences
        val encryptedSharedPreferences = EncryptedSharedPreferences.create(
            this, // context
            "secret_shared_prefs", // nazwa pliku
            masterKey, // master key
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, // szyfrowanie kluczy
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM // szyfrowanie wartości
        )

        // Generowanie klucza AES do szyfrowania danych
        secretKey = generateSecretKey()

        // Obsługa przycisku "Zapisz notatkę"
        saveButton.setOnClickListener {
            val note = noteEditText.text.toString()
            if (note.isNotEmpty()) {
                promptForPassword { password ->
                    try {
                        val encryptedNote = encrypt(note, password)
                        encryptedSharedPreferences.edit()
                            .putString("encryptedNote", encryptedNote)
                            .apply()
                        Toast.makeText(this, "Notatka zapisana!", Toast.LENGTH_SHORT).show()
                        noteEditText.text.clear()
                    } catch (e: Exception) {
                        Toast.makeText(this, "Błąd szyfrowania: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            } else {
                Toast.makeText(this, "Nie można zapisać pustej notatki!", Toast.LENGTH_SHORT).show()
            }
        }

        // Obsługa przycisku "Pokaż notatkę"
        showButton.setOnClickListener {
            val encryptedNote = encryptedSharedPreferences.getString("encryptedNote", null)
            if (encryptedNote != null) {
                promptForPassword { password ->
                    try {
                        val decryptedNote = decrypt(encryptedNote, password)
                        noteEditText.setText(decryptedNote)
                        Toast.makeText(this, "Notatka wyświetlona!", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(this, "Nieprawidłowe hasło lub błąd deszyfrowania!", Toast.LENGTH_SHORT).show()
                    }
                }
            } else {
                Toast.makeText(this, "Brak zapisanej notatki!", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // Generowanie klucza AES
    private fun generateSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256) // 256-bitowy klucz
        return keyGenerator.generateKey()
    }

    // Szyfrowanie notatki
    private fun encrypt(data: String, password: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = password.toByteArray().copyOf(12) // Użycie hasła jako IV
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    // Odszyfrowanie notatki
    private fun decrypt(encryptedData: String, password: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = password.toByteArray().copyOf(12) // Użycie hasła jako IV
        val spec = GCMParameterSpec(128, iv)
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



