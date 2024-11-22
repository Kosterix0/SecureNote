package com.example.securenotebook

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom
import javax.crypto.spec.PBEKeySpec

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button
    private lateinit var showButton: Button
    private lateinit var encryptedSharedPreferences: EncryptedSharedPreferences

    private val PASSWORD_KEY = "userPassword"
    private val SALT_KEY = "passwordSalt"
    private val FAILED_ATTEMPTS_KEY = "failedAttempts"
    private val LOCK_TIMESTAMP_KEY = "lockTimestamp"
    private val MAX_ATTEMPTS = 3
    private val LOCK_TIME_MILLIS = 60_000L // 1 minuta
    private val KEY_ALIAS = "secureKeyAlias" // alias do przechowywania klucza w Keystore

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
        val failedAttempts = encryptedSharedPreferences.getInt(FAILED_ATTEMPTS_KEY, 0)
        val lockTimestamp = encryptedSharedPreferences.getLong(LOCK_TIMESTAMP_KEY, 0)
        val currentTime = System.currentTimeMillis()

        if (lockTimestamp > currentTime) {
            val remainingTime = (lockTimestamp - currentTime) / 1000
            Toast.makeText(this, "Zablokowano. Spróbuj ponownie za ${remainingTime}s.", Toast.LENGTH_SHORT).show()
            return
        }

        if (savedHashedPassword == null || saltBase64 == null) {
            // Jeśli hasło nie jest ustawione, poproś o ustawienie nowego
            promptForNewPassword { newPassword ->
                val salt = generateSalt()
                val hashedPassword = hashPassword(newPassword, salt)
                encryptedSharedPreferences.edit()
                    .putString(PASSWORD_KEY, hashedPassword)
                    .putString(SALT_KEY, Base64.encodeToString(salt, Base64.DEFAULT))
                    .putInt(FAILED_ATTEMPTS_KEY, 0) // Reset prób
                    .apply()
                callback(newPassword)
            }
        } else {
            // Jeśli hasło jest ustawione, poproś o weryfikację
            promptForPassword { enteredPassword ->
                val salt = Base64.decode(saltBase64, Base64.DEFAULT)
                val hashedInputPassword = hashPassword(enteredPassword, salt)
                if (hashedInputPassword == savedHashedPassword) {
                    encryptedSharedPreferences.edit()
                        .putInt(FAILED_ATTEMPTS_KEY, 0) // Reset prób
                        .apply()
                    callback(enteredPassword)
                } else {
                    val newFailedAttempts = failedAttempts + 1
                    if (newFailedAttempts >= MAX_ATTEMPTS) {
                        val lockUntil = currentTime + LOCK_TIME_MILLIS
                        encryptedSharedPreferences.edit()
                            .putLong(LOCK_TIMESTAMP_KEY, lockUntil)
                            .putInt(FAILED_ATTEMPTS_KEY, 0) // Reset prób
                            .apply()
                        Toast.makeText(this, "Zablokowano na 1 minutę!", Toast.LENGTH_SHORT).show()
                    } else {
                        encryptedSharedPreferences.edit()
                            .putInt(FAILED_ATTEMPTS_KEY, newFailedAttempts)
                            .apply()
                        Toast.makeText(this, "Nieprawidłowe hasło! Próba $newFailedAttempts z $MAX_ATTEMPTS.", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    // Szyfrowanie hasła PBKDF2
    private fun hashPassword(password: String, salt: ByteArray, iterations: Int = 10000, keyLength: Int = 256): String {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, iterations, keyLength)
        val keyFactory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
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

    // Szyfrowanie notatki AES/GCM
    private fun encrypt(data: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())

        val iv = cipher.iv // Pobieramy IV wygenerowane przez system
        val encryptedData = cipher.doFinal(data.toByteArray())

        // Łączymy IV z zaszyfrowanymi danymi i kodujemy to w Base64
        val output = iv + encryptedData
        return Base64.encodeToString(output, Base64.DEFAULT)
    }

    // Deszyfrowanie notatki AES/GCM
    private fun decrypt(data: String): String {
        val decoded = Base64.decode(data, Base64.DEFAULT)

        // Rozdzielenie IV i zaszyfrowanych danych
        val iv = decoded.copyOfRange(0, 12)
        val encryptedData = decoded.copyOfRange(12, decoded.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(), spec)

        val decryptedBytes = cipher.doFinal(encryptedData)
        return String(decryptedBytes)
    }

    // Pobranie lub wygenerowanie klucza szyfrowania z Android Keystore
    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        // Sprawdzanie, czy klucz już istnieje
        return if (keyStore.containsAlias(KEY_ALIAS)) {
            (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        } else {
            // Generowanie nowego klucza, jeśli nie istnieje
            val keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore")
            val keyGenSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            keyGenerator.init(keyGenSpec)
            keyGenerator.generateKey()
        }
    }
}








