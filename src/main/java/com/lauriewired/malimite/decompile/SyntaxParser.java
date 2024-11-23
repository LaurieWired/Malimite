package com.lauriewired.malimite.decompile;

import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.tree.*;

import com.lauriewired.malimite.decompile.antlr.CBaseVisitor;
import com.lauriewired.malimite.decompile.antlr.CLexer;
import com.lauriewired.malimite.decompile.antlr.CParser;

public class SyntaxParser {

    /**
     * Parses the given C code using ANTLR and returns the parse tree.
     */
    public ParseTree parseCode(String code) {
        try {
            // Create a CharStream from the input code
            CharStream input = CharStreams.fromString(code);
            CLexer lexer = new CLexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            CParser parser = new CParser(tokens);

            // Attach a custom error listener for handling errors
            parser.removeErrorListeners();
            parser.addErrorListener(new SyntaxErrorListener());

            // Parse the code and return the parse tree
            return parser.compilationUnit();
        } catch (Exception e) {
            System.err.println("Error during parsing: " + e.getMessage());
            return null;
        }
    }

    /**
     * Custom error listener to handle syntax errors gracefully.
     */
    private static class SyntaxErrorListener extends BaseErrorListener {
        @Override
        public void syntaxError(Recognizer<?, ?> recognizer, Object offendingSymbol,
                                int line, int charPositionInLine, String msg, RecognitionException e) {
            // Handle syntax errors here (log, recover, etc.)
            System.err.printf("Syntax Error at line %d:%d - %s%n", line, charPositionInLine, msg);
        }
    }

    /**
     * Converts the given parse tree back into a formatted C-like code string.
     */
    public String reprintCode(ParseTree tree) {
        if (tree == null) {
            return "Error: Unable to parse input code.";
        }

        CCodeReprinter reprinter = new CCodeReprinter();
        return reprinter.visit(tree);
    }

    /**
     * Visitor class for reconstructing C code from the parse tree.
     */
    private static class CCodeReprinter extends CBaseVisitor<String> {
        @Override
        public String visitChildren(RuleNode node) {
            if (node == null) return "";
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < node.getChildCount(); i++) {
                result.append(visit(node.getChild(i)));
            }
            return result.toString();
        }

        @Override
        public String visitTerminal(TerminalNode node) {
            return node.getText() + " ";
        }

        @Override
        public String visitErrorNode(ErrorNode node) {
            return "/* ERROR */ ";
        }
    }
}