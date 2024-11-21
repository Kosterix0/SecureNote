package com.example.securenotebook

import android.content.Context
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast

class MainActivity : AppCompatActivity() {

    private lateinit var noteEditText: EditText
    private lateinit var saveButton: Button

    private val NOTE_KEY = "saved_note"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Inicjalizacja widoków
        noteEditText = findViewById(R.id.noteEditText)
        saveButton = findViewById(R.id.saveButton)

        // Wczytaj zapisaną notatkę
        loadNote()

        // Obsługa zapisu notatki
        saveButton.setOnClickListener {
            saveNote()
        }
    }

    private fun loadNote() {
        val sharedPreferences = getSharedPreferences("SecureNotebookPrefs", Context.MODE_PRIVATE)
        val savedNote = sharedPreferences.getString(NOTE_KEY, "")
        noteEditText.setText(savedNote)
    }

    private fun saveNote() {
        val noteContent = noteEditText.text.toString()
        val sharedPreferences = getSharedPreferences("SecureNotebookPrefs", Context.MODE_PRIVATE)
        val editor = sharedPreferences.edit()
        editor.putString(NOTE_KEY, noteContent)
        editor.apply()

        Toast.makeText(this, "Notatka zapisana!", Toast.LENGTH_SHORT).show()
    }
}
