package com.lauriewired.malimite.ui;

import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import java.awt.event.KeyEvent;
import java.awt.event.InputEvent;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.swing.JFrame;

public class KeyboardShortcuts {
    private static final Logger LOGGER = Logger.getLogger(KeyboardShortcuts.class.getName());

    public static void setupShortcuts(RSyntaxTextArea textArea, JFrame parentFrame) {
        // Add 'x' key binding for references
        textArea.getInputMap().put(KeyStroke.getKeyStroke('x'), "showReferences");
        textArea.getActionMap().put("showReferences", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                showReferencesForSelectedWord(textArea, parentFrame);
            }
        });
    }

    private static void showReferencesForSelectedWord(RSyntaxTextArea textArea, JFrame parentFrame) {
        String selectedText = textArea.getSelectedText();
        
        // If no text is selected, try to get the word at the cursor
        if (selectedText == null || selectedText.trim().isEmpty()) {
            try {
                int caretPos = textArea.getCaretPosition();
                int start = getWordStart(textArea.getText(), caretPos);
                int end = getWordEnd(textArea.getText(), caretPos);
                if (start != -1 && end != -1) {
                    selectedText = textArea.getText(start, end - start);
                }
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, "Error getting word at cursor", ex);
                return;
            }
        }

        // Only proceed if we have a word and we're in a class context
        if (selectedText != null && !selectedText.trim().isEmpty()) {
            String currentClassName = AnalysisWindow.getCurrentClassName();
            if (currentClassName != null && !currentClassName.isEmpty()) {
                ReferencesDialog.show(parentFrame, 
                    AnalysisWindow.getDbHandler(), 
                    selectedText.trim(), 
                    AnalysisWindow.getCurrentClassName(),
                    AnalysisWindow.getCurrentFunctionName(),
                    AnalysisWindow.getCurrentExecutableName());
            }
        }
    }

    private static int getWordStart(String text, int pos) {
        if (pos <= 0 || pos >= text.length()) return -1;
        
        while (pos > 0 && isWordChar(text.charAt(pos - 1))) {
            pos--;
        }
        return pos;
    }

    private static int getWordEnd(String text, int pos) {
        if (pos < 0 || pos >= text.length()) return -1;
        
        while (pos < text.length() && isWordChar(text.charAt(pos))) {
            pos++;
        }
        return pos;
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }
} 