package com.lauriewired.malimite.ui;

import java.awt.Color;
import java.awt.Container;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.UIManager;

import org.fife.ui.rtextarea.RTextScrollPane;
import org.fife.ui.rtextarea.Gutter;
import org.fife.ui.rsyntaxtextarea.AbstractTokenMakerFactory;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rsyntaxtextarea.TokenMakerFactory;
import org.fife.ui.rtextarea.SmartHighlightPainter;
import javax.swing.text.Highlighter;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.HashMap;
import java.util.Map;
import com.lauriewired.malimite.tools.RuntimeMethodHandler;
import org.fife.ui.rsyntaxtextarea.Style;

public class SyntaxHighlighter {

    private static final Logger LOGGER = Logger.getLogger(SyntaxHighlighter.class.getName());
    private static final Color HIGHLIGHT_COLOR = new Color(255, 255, 0, 70);
    private static final List<Object> wordHighlights = new ArrayList<>(); // Track word highlights
    private static final Map<String, Color> customWordColors = new HashMap<>();

    public static void applyCustomTheme(RSyntaxTextArea textArea) {
        // Register the custom TokenMaker for the C++ syntax style
        AbstractTokenMakerFactory factory = (AbstractTokenMakerFactory) TokenMakerFactory.getDefaultInstance();
        factory.putMapping(SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS, "com.lauriewired.malimite.ui.CustomTokenMaker");
        
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS);

        // Get the current theme's background color from UIManager
        Color themeBackground = UIManager.getColor("Panel.background");
        if (themeBackground == null) {
            // Fallback if UIManager color is not available
            themeBackground = textArea.getBackground();
        }
    
        boolean isDarkTheme = isDarkTheme(themeBackground);
    
        // Reset the syntax scheme to ensure clean state
        textArea.setSyntaxScheme(new SyntaxScheme(true));
        SyntaxScheme scheme = textArea.getSyntaxScheme();
        
        // Ensure the scheme can handle our custom token
        Color runtimeMethodColor = isDarkTheme 
            ? new Color(210, 240, 255)  // Very light blue for dark theme (much lighter than #9CDCFE)
            : new Color(0, 150, 255);   // Brighter blue for light theme (lighter than #001080)
        scheme.setStyle(CustomTokenMaker.RUNTIME_METHOD, new Style(runtimeMethodColor));
    
        // Background colors based on the theme
        Color editorBackground = isDarkTheme ? themeBackground : Color.WHITE;  // Use white for light theme
        Color lineHighlight = isDarkTheme ? 
            adjustBrightness(themeBackground, 1.2f) : 
            new Color(240, 240, 240);  // Light gray for light theme
        Color lineNumberBackground = isDarkTheme ? themeBackground : Color.WHITE;
        //Color lineNumberForeground = isDarkTheme ? Color.decode("#CCCCCC") : Color.decode("#333333");
    
        // Set the syntax colors for the theme
        if (isDarkTheme) {
            Color dataTypeColor = Color.decode("#4EC9B0");
            Color booleanColor = Color.decode("#569CD6");
            scheme.getStyle(Token.RESERVED_WORD).foreground = Color.decode("#569CD6");
            scheme.getStyle(Token.RESERVED_WORD_2).foreground = dataTypeColor;
            scheme.getStyle(Token.DATA_TYPE).foreground = dataTypeColor;
            scheme.getStyle(Token.FUNCTION).foreground = Color.decode("#DCDCAA");
            scheme.getStyle(Token.LITERAL_NUMBER_DECIMAL_INT).foreground = Color.decode("#D7BA7D");
            scheme.getStyle(Token.LITERAL_NUMBER_HEXADECIMAL).foreground = Color.decode("#D7BA7D");
            scheme.getStyle(Token.LITERAL_BOOLEAN).foreground = booleanColor;
            scheme.getStyle(Token.LITERAL_STRING_DOUBLE_QUOTE).foreground = Color.decode("#CE9178");
            scheme.getStyle(Token.COMMENT_MULTILINE).foreground = Color.decode("#57A64A");
            scheme.getStyle(Token.COMMENT_DOCUMENTATION).foreground = Color.decode("#57A64A");
            scheme.getStyle(Token.COMMENT_EOL).foreground = Color.decode("#57A64A");
            scheme.getStyle(Token.OPERATOR).foreground = Color.WHITE;
            scheme.getStyle(Token.SEPARATOR).foreground = Color.WHITE;
            scheme.getStyle(Token.IDENTIFIER).foreground = Color.decode("#9CDCFE");
            // XML-specific colors for dark theme
            scheme.getStyle(Token.MARKUP_TAG_DELIMITER).foreground = Color.decode("#808080");    // Gray for < > /
            scheme.getStyle(Token.MARKUP_TAG_NAME).foreground = Color.decode("#569CD6");         // Blue for tag names
            scheme.getStyle(Token.MARKUP_TAG_ATTRIBUTE).foreground = Color.decode("#9CDCFE");    // Light blue for attributes
            scheme.getStyle(Token.MARKUP_TAG_ATTRIBUTE_VALUE).foreground = Color.decode("#CE9178"); // Orange for values
        } else {
            Color booleanColor = Color.decode("#0451A5");
            Color keyColor = Color.decode("#4A7A4F"); // Soft green for keys
            Color valueColor = Color.decode("#376E9B"); // Soft blue for values
            scheme.getStyle(Token.RESERVED_WORD).foreground = Color.decode("#0000FF");
            scheme.getStyle(Token.DATA_TYPE).foreground = Color.decode("#267F99");
            scheme.getStyle(Token.FUNCTION).foreground = Color.decode("#795E26");
            scheme.getStyle(Token.LITERAL_NUMBER_DECIMAL_INT).foreground = Color.decode("#098658");
            scheme.getStyle(Token.LITERAL_NUMBER_HEXADECIMAL).foreground = Color.decode("#098658");
            scheme.getStyle(Token.LITERAL_BOOLEAN).foreground = booleanColor;
            scheme.getStyle(Token.LITERAL_STRING_DOUBLE_QUOTE).foreground = valueColor; // Soft blue for values
            scheme.getStyle(Token.MARKUP_TAG_NAME).foreground = keyColor; // Soft green for tag names (keys)
            scheme.getStyle(Token.COMMENT_MULTILINE).foreground = Color.decode("#008000");
            scheme.getStyle(Token.COMMENT_DOCUMENTATION).foreground = Color.decode("#008000");
            scheme.getStyle(Token.COMMENT_EOL).foreground = Color.decode("#008000");
            scheme.getStyle(Token.OPERATOR).foreground = Color.decode("#333333");
            scheme.getStyle(Token.SEPARATOR).foreground = Color.decode("#333333");
            scheme.getStyle(Token.IDENTIFIER).foreground = Color.decode("#001080");
            // XML-specific colors for light theme
            scheme.getStyle(Token.MARKUP_TAG_DELIMITER).foreground = Color.decode("#800000");    // Dark red for < > /
            scheme.getStyle(Token.MARKUP_TAG_NAME).foreground = Color.decode("#800000");         // Dark red for tag names
            scheme.getStyle(Token.MARKUP_TAG_ATTRIBUTE).foreground = Color.decode("#FF0000");    // Red for attributes
            scheme.getStyle(Token.MARKUP_TAG_ATTRIBUTE_VALUE).foreground = Color.decode("#0000FF"); // Blue for values
        }
    
        // Apply background colors
        textArea.setBackground(editorBackground);
        textArea.setCurrentLineHighlightColor(lineHighlight);
        textArea.setFadeCurrentLineHighlight(true);
    
        // Reset gutter colors directly to ensure the change applies
        Container parent = textArea.getParent();
        if (parent != null && parent.getParent() instanceof RTextScrollPane) {
            RTextScrollPane scrollPane = (RTextScrollPane) parent.getParent();
            Gutter gutter = scrollPane.getGutter();
            gutter.setBackground(lineNumberBackground);
            //gutter.setLineNumberColor(lineNumberForeground);
            //gutter.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        }
    
        // Add these lines after setting the background colors
        Color selectionColor = isDarkTheme ? 
            new Color(51, 153, 255, 90) :  // Semi-transparent blue for dark theme
            new Color(51, 153, 255, 50);   // Lighter blue for light theme
        textArea.setSelectionColor(selectionColor);
    
        textArea.revalidate();
        textArea.repaint();
    }    

    private static boolean isDarkTheme(Color background) {
        double brightness = (background.getRed() * 0.299 + 
                           background.getGreen() * 0.587 + 
                           background.getBlue() * 0.114) / 255;
        return brightness < 0.5;
    }

    private static Color adjustBrightness(Color color, float factor) {
        float[] hsb = Color.RGBtoHSB(color.getRed(), color.getGreen(), color.getBlue(), null);
        hsb[2] = Math.min(1.0f, hsb[2] * factor); // Adjust brightness
        return Color.getHSBColor(hsb[0], hsb[1], hsb[2]);
    }

    public static void setupWordHighlighting(RSyntaxTextArea textArea) {
        // Use a distinct color for word highlights
        Color wordHighlightColor = HIGHLIGHT_COLOR;
        Highlighter.HighlightPainter painter = new SmartHighlightPainter(wordHighlightColor);
    
        // Add a caret listener to dynamically highlight words at the caret
        textArea.addCaretListener(e -> {
            try {
                int caretPos = textArea.getCaretPosition();
                highlightWordAtCaret(textArea, caretPos, painter);
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, "Error during word highlighting", ex);
            }
        });
    }

    private static void highlightWordAtCaret(RSyntaxTextArea textArea, int caretPos, Highlighter.HighlightPainter painter) {
        try {
            // Remove only word highlights
            Highlighter highlighter = textArea.getHighlighter();
            for (Object highlight : wordHighlights) {
                highlighter.removeHighlight(highlight);
            }
            wordHighlights.clear(); // Clear the tracking list

            // Get the word at the caret or the selected text
            String selectedText = textArea.getSelectedText();
            if (selectedText == null || selectedText.trim().isEmpty()) {
                selectedText = getWordAtCaret(textArea.getText(), caretPos);
            }

            if (selectedText == null || selectedText.trim().isEmpty()) {
                return;
            }

            // Highlight all occurrences of the word
            String text = textArea.getText();
            String wordRegex = "\\b" + Pattern.quote(selectedText.trim()) + "\\b";
            Pattern pattern = Pattern.compile(wordRegex);
            Matcher matcher = pattern.matcher(text);

            while (matcher.find()) {
                Object highlight = highlighter.addHighlight(matcher.start(), matcher.end(), painter);
                wordHighlights.add(highlight); // Track this highlight
            }
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, "Error highlighting text", ex);
        }
    }

    private static String getWordAtCaret(String text, int caretPos) {
        if (caretPos < 0 || caretPos >= text.length()) return null;
    
        int start = caretPos;
        int end = caretPos;
    
        // Find the start of the word
        while (start > 0 && isWordChar(text.charAt(start - 1))) {
            start--;
        }
    
        // Find the end of the word
        while (end < text.length() && isWordChar(text.charAt(end))) {
            end++;
        }
    
        if (start < end) {
            return text.substring(start, end);
        }
        return null;
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }
}