package com.lauriewired.malimite.ui;

import javax.swing.text.Segment;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rsyntaxtextarea.modes.CPlusPlusTokenMaker;
import com.lauriewired.malimite.tools.RuntimeMethodHandler;

public class CustomTokenMaker extends CPlusPlusTokenMaker {
    // Custom token type for runtime methods
    public static final int RUNTIME_METHOD = Token.IDENTIFIER + 1;

    @Override
    public Token getTokenList(Segment text, int initialTokenType, int startOffset) {
        // Use parent method to generate initial token list
        Token tokenList = super.getTokenList(text, initialTokenType, startOffset);
        Token t = tokenList;

        // Traverse the token list
        while (t != null && t.isPaintable()) {
            if (t.getType() == TokenTypes.IDENTIFIER) {
                String lexeme = t.getLexeme();

                // Check for runtime method prefixes
                if (lexeme.startsWith("_swift_") || lexeme.startsWith("_objc_")) {
                    if (RuntimeMethodHandler.isSwiftRuntimeMethod(lexeme)) {
                        t.setType(RUNTIME_METHOD); // Assign custom token type
                    }
                }
            }
            t = t.getNextToken(); // Move to the next token
        }
        return tokenList;
    }
}
