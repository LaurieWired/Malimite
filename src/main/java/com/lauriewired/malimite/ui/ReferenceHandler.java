package com.lauriewired.malimite.ui;

import javax.swing.*;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import java.awt.event.KeyEvent;
import java.awt.event.KeyAdapter;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.lauriewired.malimite.database.SQLiteDBHandler;

public class ReferenceHandler {
    private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("[a-zA-Z_$][a-zA-Z0-9_$]*");

    public static void attachTo(RSyntaxTextArea textArea, JFrame parent, String className, SQLiteDBHandler dbHandler, String functionName, String executableName) {
        textArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyChar() == 'x' || e.getKeyChar() == 'X') {
                    handleReferenceRequest(textArea, parent, className, dbHandler, functionName, executableName);
                }
            }
        });
    }

    public static void handleReferenceRequest(RSyntaxTextArea textArea, JFrame parent, String className, SQLiteDBHandler dbHandler, String functionName, String executableName) {
        String selectedText = textArea.getSelectedText();
        
        if (selectedText == null || selectedText.trim().isEmpty()) {
            // If no text is selected, try to get the word at cursor
            selectedText = getWordAtCursor(textArea);
            if (selectedText == null) return;
        }

        selectedText = selectedText.trim();
        
        // Verify it's a valid identifier
        if (!IDENTIFIER_PATTERN.matcher(selectedText).matches()) {
            return;
        }

        // Show the references dialog
        ReferencesDialog.show(parent, dbHandler, selectedText, className, functionName, executableName);
    }

    public static void handleReferenceRequest(JFrame parent, String className, SQLiteDBHandler dbHandler, String functionName, String executableName) {
        // Show the references dialog without a specific selection
        ReferencesDialog.show(parent, dbHandler, null, className, functionName, executableName);
    }

    private static String getWordAtCursor(RSyntaxTextArea textArea) {
        try {
            int caretPos = textArea.getCaretPosition();
            String text = textArea.getText();
            
            // Find word boundaries
            int start = caretPos;
            int end = caretPos;

            // Look backwards for start of word
            while (start > 0 && isWordChar(text.charAt(start - 1))) {
                start--;
            }

            // Look forwards for end of word
            while (end < text.length() && isWordChar(text.charAt(end))) {
                end++;
            }

            if (start != end) {
                return text.substring(start, end);
            }
        } catch (Exception e) {
            // Handle any potential exceptions gracefully
            return null;
        }
        return null;
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$';
    }
} 