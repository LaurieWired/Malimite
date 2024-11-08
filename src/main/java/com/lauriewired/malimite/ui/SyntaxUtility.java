package com.lauriewired.malimite.ui;

import java.awt.Color;
import java.awt.Container;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.UIManager;

import org.fife.ui.rtextarea.RTextScrollPane;
import org.fife.ui.rtextarea.Gutter;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;

public class SyntaxUtility {

    public static void applyCustomTheme(RSyntaxTextArea textArea) {
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
    
        // Background colors based on the theme
        Color editorBackground = themeBackground;
        Color lineHighlight = adjustBrightness(themeBackground, isDarkTheme ? 1.2f : 0.95f);
        Color lineNumberBackground = themeBackground;
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
        } else {
            // Light mode with additional tokens for XML styling
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
}