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
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button
    private lateinit var showButton: Button
    private lateinit var secretKey: SecretKey
    private lateinit var encryptedSharedPreferences: EncryptedSharedPreferences

    private val PASSWORD_KEY = "userPassword"
    private val SALT_KEY = "passwordSalt"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Inicjalizacja widoków
        noteEditText = findViewById(R.id.noteEditText)
        saveButton = findViewById(R.id.saveButton)
        showButton = findViewById(R.id.showButton)

        // Tworzenie EncryptedSharedPreferences
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        encryptedSharedPreferences = EncryptedSharedPreferences.create(
            this,
            "secret_shared_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ) as EncryptedSharedPreferences

        // Inicjalizacja lub załadowanie klucza szyfrującego
        secretKey = getOrCreateSecretKey()

        // Obsługa przycisku "Zapisz notatkę"
        saveButton.setOnClickListener {
            handlePassword { password ->
                val note = noteEditText.text.toString()
                if (note.isNotEmpty()) {
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
                } else {
                    Toast.makeText(this, "Nie można zapisać pustej notatki!", Toast.LENGTH_SHORT).show()
                }
            }
        }

        // Obsługa przycisku "Pokaż notatkę"
        showButton.setOnClickListener {
            handlePassword { password ->
                val encryptedNote = encryptedSharedPreferences.getString("encryptedNote", null)
                if (encryptedNote != null) {
                    try {
                        val decryptedNote = decrypt(encryptedNote)
                        noteEditText.setText(decryptedNote)
                        Toast.makeText(this, "Notatka wyświetlona!", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(this, "Nieprawidłowe hasło lub błąd deszyfrowania!", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(this, "Brak zapisanej notatki!", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    // Obsługa ustawiania i weryfikacji hasła
    private fun handlePassword(callback: (String) -> Unit) {
        val savedHashedPassword = encryptedSharedPreferences.getString(PASSWORD_KEY, null)
        val saltBase64 = encryptedSharedPreferences.getString(SALT_KEY, null)

        if (savedHashedPassword == null || saltBase64 == null) {
            // Jeśli hasło nie jest ustawione, poproś o ustawienie nowego
            promptForNewPassword { newPassword ->
                val salt = generateSalt()
                val hashedPassword = hashPassword(newPassword, salt)
                encryptedSharedPreferences.edit()
                    .putString(PASSWORD_KEY, hashedPassword)
                    .putString(SALT_KEY, Base64.encodeToString(salt, Base64.DEFAULT))
                    .apply()
                callback(newPassword)
            }
        } else {
            // Jeśli hasło jest ustawione, poproś o weryfikację
            promptForPassword { enteredPassword ->
                val salt = Base64.decode(saltBase64, Base64.DEFAULT)
                val hashedInputPassword = hashPassword(enteredPassword, salt)
                if (hashedInputPassword == savedHashedPassword) {
                    callback(enteredPassword)
                } else {
                    Toast.makeText(this, "Nieprawidłowe hasło!", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    // Szyfrowanie hasła PBKDF2
    private fun hashPassword(password: String, salt: ByteArray, iterations: Int = 10000, keyLength: Int = 256): String {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, iterations, keyLength)
        val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val hashedBytes = keyFactory.generateSecret(keySpec).encoded
        return Base64.encodeToString(hashedBytes, Base64.DEFAULT)
    }

    // Generowanie soli
    private fun generateSalt(): ByteArray {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        return salt
    }

    // Okno dialogowe do wprowadzenia nowego hasła
    private fun promptForNewPassword(callback: (String) -> Unit) {
        val passwordInput = EditText(this)
        val dialog = AlertDialog.Builder(this)
            .setTitle("Ustaw nowe hasło")
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

    // Okno dialogowe do podania istniejącego hasła
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

    // Szyfrowanie danych
    private fun encrypt(data: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        val encryptedBytes = cipher.doFinal(data.toByteArray())

        val combined = iv + encryptedBytes
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    // Odszyfrowywanie danych
    private fun decrypt(encryptedData: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val combined = Base64.decode(encryptedData, Base64.DEFAULT)

        val iv = combined.copyOfRange(0, 12)
        val encryptedBytes = combined.copyOfRange(12, combined.size)

        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }

    // Pobieranie lub generowanie klucza szyfrującego
    private fun getOrCreateSecretKey(): SecretKey {
        val keyAlias = "secureNotebookKey"
        val encryptedKey = encryptedSharedPreferences.getString(keyAlias, null)

        return if (encryptedKey != null) {
            val keyBytes = Base64.decode(encryptedKey, Base64.DEFAULT)
            SecretKeySpec(keyBytes, "AES")
        } else {
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
        keyGenerator.init(256)
        return keyGenerator.generateKey()
    }
}





