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
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button
    private lateinit var showButton: Button
    private lateinit var secretKey: SecretKey
    private lateinit var encryptedSharedPreferences: EncryptedSharedPreferences

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
        encryptedSharedPreferences = EncryptedSharedPreferences.create(
            this, // context
            "secret_shared_prefs", // nazwa pliku
            masterKey, // master key
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, // szyfrowanie kluczy
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM // szyfrowanie wartości
        ) as EncryptedSharedPreferences

        // Inicjalizacja lub załadowanie klucza szyfrującego
        secretKey = getOrCreateSecretKey()

        // Obsługa przycisku "Zapisz notatkę"
        saveButton.setOnClickListener {
            val note = noteEditText.text.toString()
            if (note.isNotEmpty()) {
                promptForPassword { password ->
                    try {
                        val encryptedNote = encrypt(note)
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
                promptForPassword {  password ->
                    try {
                        val decryptedNote = decrypt(encryptedNote)
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

    // Pobieranie lub generowanie klucza szyfrującego
    private fun getOrCreateSecretKey(): SecretKey {
        val keyAlias = "secureNotebookKey"
        val encryptedKey = encryptedSharedPreferences.getString(keyAlias, null)

        return if (encryptedKey != null) {
            // Klucz już istnieje, odszyfruj i zwróć
            val keyBytes = Base64.decode(encryptedKey, Base64.DEFAULT)
            SecretKeySpec(keyBytes, "AES")
        } else {
            // Klucz nie istnieje, wygeneruj nowy
            val newKey = generateSecretKey()
            val keyBytes = newKey.encoded
            val encryptedKey = Base64.encodeToString(keyBytes, Base64.DEFAULT)
            encryptedSharedPreferences.edit()
                .putString(keyAlias, encryptedKey)
                .apply()
            newKey
        }
    }

    // Generowanie klucza AES
    private fun generateSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256) // 256-bitowy klucz
        return keyGenerator.generateKey()
    }

    // Szyfrowanie notatki
    private fun encrypt(data: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12) // IV o długości 12 bajtów
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        val encryptedBytes = cipher.doFinal(data.toByteArray())

        // Dołącz IV do szyfrowanej wiadomości
        val combined = iv + encryptedBytes
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    // Odszyfrowanie notatki
    private fun decrypt(encryptedData: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val combined = Base64.decode(encryptedData, Base64.DEFAULT)

        // Oddziel IV od danych
        val iv = combined.copyOfRange(0, 12)
        val encryptedBytes = combined.copyOfRange(12, combined.size)

        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
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



