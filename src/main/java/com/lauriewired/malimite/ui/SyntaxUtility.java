package com.lauriewired.malimite.ui;

import java.awt.Color;
import java.awt.Container;

import javax.swing.UIManager;

import org.fife.ui.rtextarea.RTextScrollPane;
import org.fife.ui.rtextarea.Gutter;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;

public class SyntaxUtility {

    public static void applyCustomTheme(RSyntaxTextArea textArea) {
        SyntaxScheme scheme = textArea.getSyntaxScheme();
        
        // Get the current theme's background color from the text area's parent
        Color themeBackground = UIManager.getColor("Panel.background");
        boolean isDarkTheme = isDarkTheme(themeBackground);
        
        // Derive colors based on the theme background
        Color editorBackground = adjustBrightness(themeBackground, isDarkTheme ? 0.9f : 1.1f);
        Color lineHighlight = adjustBrightness(themeBackground, isDarkTheme ? 1.2f : 0.95f);
        Color lineNumberBackground = isDarkTheme ? Color.decode("#333333") : Color.decode("#F0F0F0");
        Color lineNumberForeground = isDarkTheme ? Color.decode("#CCCCCC") : Color.decode("#333333");

        // Apply the theme colors to syntax elements
        if (isDarkTheme) {
            scheme.getStyle(Token.RESERVED_WORD).foreground = Color.decode("#569CD6");
            scheme.getStyle(Token.DATA_TYPE).foreground = Color.decode("#4EC9B0");
            scheme.getStyle(Token.FUNCTION).foreground = Color.decode("#DCDCAA");
            scheme.getStyle(Token.LITERAL_NUMBER_DECIMAL_INT).foreground = Color.decode("#B5CEA8");
            scheme.getStyle(Token.LITERAL_STRING_DOUBLE_QUOTE).foreground = Color.decode("#CE9178");
            scheme.getStyle(Token.COMMENT_MULTILINE).foreground = Color.decode("#57A64A");
            scheme.getStyle(Token.COMMENT_DOCUMENTATION).foreground = Color.decode("#57A64A");
            scheme.getStyle(Token.COMMENT_EOL).foreground = Color.decode("#57A64A");
            scheme.getStyle(Token.OPERATOR).foreground = Color.WHITE;
            scheme.getStyle(Token.SEPARATOR).foreground = Color.WHITE;
            scheme.getStyle(Token.IDENTIFIER).foreground = Color.decode("#9CDCFE");
        } else {
            scheme.getStyle(Token.RESERVED_WORD).foreground = Color.decode("#0000FF");
            scheme.getStyle(Token.DATA_TYPE).foreground = Color.decode("#267F99");
            scheme.getStyle(Token.FUNCTION).foreground = Color.decode("#795E26");
            scheme.getStyle(Token.LITERAL_NUMBER_DECIMAL_INT).foreground = Color.decode("#098658");
            scheme.getStyle(Token.LITERAL_STRING_DOUBLE_QUOTE).foreground = Color.decode("#A31515");
            scheme.getStyle(Token.COMMENT_MULTILINE).foreground = Color.decode("#008000");
            scheme.getStyle(Token.COMMENT_DOCUMENTATION).foreground = Color.decode("#008000");
            scheme.getStyle(Token.COMMENT_EOL).foreground = Color.decode("#008000");
            scheme.getStyle(Token.OPERATOR).foreground = Color.BLACK;
            scheme.getStyle(Token.SEPARATOR).foreground = Color.BLACK;
            scheme.getStyle(Token.IDENTIFIER).foreground = Color.decode("#001080");
        }

        // These styles are shared between both themes
        scheme.getStyle(Token.RESERVED_WORD_2).foreground = scheme.getStyle(Token.RESERVED_WORD).foreground;
        scheme.getStyle(Token.LITERAL_BOOLEAN).foreground = scheme.getStyle(Token.RESERVED_WORD).foreground;

        // Apply theme-aware background colors
        textArea.setBackground(editorBackground);
        textArea.setCurrentLineHighlightColor(lineHighlight);
        textArea.setFadeCurrentLineHighlight(true);

        // Only try to update gutter colors if the text area is properly initialized
        Container parent = textArea.getParent();
        if (parent != null && parent.getParent() instanceof RTextScrollPane) {
            RTextScrollPane scrollPane = (RTextScrollPane) parent.getParent();
            Gutter gutter = scrollPane.getGutter();
            gutter.setBackground(lineNumberBackground);
            gutter.setLineNumberColor(lineNumberForeground);
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