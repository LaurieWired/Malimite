package com.lauriewired.malimite.decompile;

import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.tree.*;

import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.decompile.antlr.CPP14ParserBaseVisitor;
import com.lauriewired.malimite.decompile.antlr.CPP14Lexer;
import com.lauriewired.malimite.decompile.antlr.CPP14Parser;

import java.util.logging.Level;
import java.util.logging.Logger;

public class SyntaxParser {
    private CPP14Lexer lexer;
    private CPP14Parser parser;
    private static final Logger LOGGER = Logger.getLogger(SyntaxParser.class.getName());
    private SQLiteDBHandler dbHandler;
    private String currentFunction;
    private String currentClass;

    public SyntaxParser(SQLiteDBHandler dbHandler) {
        this.dbHandler = dbHandler;
    }

    public void setContext(String functionName, String className) {
        this.currentFunction = functionName;
        this.currentClass = className;
    }

    public ParseTree parseCode(String code) {
        try {
            CharStream input = CharStreams.fromString(code);
            lexer = new CPP14Lexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            parser = new CPP14Parser(tokens);
            
            // First pass: collect cross-references
            ParseTree tree = parser.translationUnit();
            if (dbHandler != null && currentFunction != null && currentClass != null) {
                new CrossReferenceVisitor().visit(tree);
            }
            
            return tree;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error parsing code", e);
            return null;
        }
    }

    private class CrossReferenceVisitor extends CPP14ParserBaseVisitor<Void> {
        @Override
        public Void visitPostfixExpression(CPP14Parser.PostfixExpressionContext ctx) {
            String calledFunction = ctx.getText();
            // Extract the class name if it's a method call (contains ::)
            String calledClass = null;
            if (calledFunction.contains("::")) {
                String[] parts = calledFunction.split("::");
                calledClass = parts[0];
                calledFunction = parts[1];
            }

            // Store the cross-reference
            dbHandler.insertCrossReference(
                "CALLS",
                currentFunction,
                currentClass,
                calledFunction,
                calledClass != null ? calledClass : "Unknown",
                ctx.getStart().getLine()
            );

            return visitChildren(ctx);
        }

        @Override
        public Void visitDeclarationStatement(CPP14Parser.DeclarationStatementContext ctx) {
            if (ctx.blockDeclaration() != null && ctx.blockDeclaration().simpleDeclaration() != null) {
                String variableType = ctx.blockDeclaration().simpleDeclaration().declSpecifierSeq().getText();
                String variableName = ctx.blockDeclaration().simpleDeclaration().initDeclaratorList().getText();
                
                // Clean up variable name (remove initialization if present)
                if (variableName.contains("=")) {
                    variableName = variableName.substring(0, variableName.indexOf("=")).trim();
                }

                // Store the type information
                dbHandler.insertTypeInformation(
                    variableName,
                    variableType,
                    currentFunction,
                    currentClass,
                    ctx.getStart().getLine()
                );
            }
            return visitChildren(ctx);
        }

        @Override
        public Void visitIdExpression(CPP14Parser.IdExpressionContext ctx) {
            String reference = ctx.getText();
            
            if (reference.contains("::")) {
                String referencedClass = reference.split("::")[0];
                
                // Store class usage reference
                dbHandler.insertCrossReference(
                    "USES_CLASS",
                    currentFunction,
                    currentClass,
                    null,
                    referencedClass,
                    ctx.getStart().getLine()
                );
            }

            return visitChildren(ctx);
        }
    }

    public String reprintCode(ParseTree tree) {
        if (tree == null) return "";
    
        return new CPP14ParserBaseVisitor<String>() {
            private int indentLevel = 0;
            private static final String INDENT = "    "; // 4 spaces per indent level
    
            @Override
            public String visitChildren(RuleNode node) {
                StringBuilder result = new StringBuilder();
                int n = node.getChildCount();
    
                for (int i = 0; i < n; i++) {
                    ParseTree child = node.getChild(i);
                    String childResult = child.accept(this);
    
                    if (childResult != null) {
                        if (isOpeningBrace(childResult)) {
                            result.append(" {\n");
                            indentLevel++;
                            result.append(getIndentation());
                        } else if (isClosingBrace(childResult)) {
                            result.append("\n");
                            indentLevel--;
                            result.append(getIndentation()).append("}");
                        } else if (isControlKeyword(childResult)) {
                            result.append("\n").append(getIndentation()).append(childResult).append(" ");
                        } else if (needsNewline(child)) {
                            result.append(childResult).append("\n");
                            result.append(getIndentation());
                        } else {
                            result.append(childResult);
                            if (i < n - 1 && needsSpace(child, node.getChild(i + 1))) {
                                result.append(" ");
                            }
                        }
                    }
                }
                return result.toString();
            }
    
            @Override
            public String visitTerminal(TerminalNode node) {
                return formatToken(node.getText());
            }
    
            private boolean needsNewline(ParseTree node) {
                String text = node.getText();
                return text.equals(";") || text.equals("{") || text.equals("}");
            }
    
            private boolean needsSpace(ParseTree left, ParseTree right) {
                String leftText = left.getText();
                String rightText = right.getText();
                
                // Don't add space around "::" operator
                if (leftText.equals("::") || rightText.equals("::")) {
                    return false;
                }
                
                // Don't add space before/after certain punctuation
                if (isPunctuation(leftText) || isPunctuation(rightText)) {
                    return false;
                }
                return true;
            }
    
            private boolean isOpeningBrace(String text) {
                return text.equals("{");
            }
    
            private boolean isClosingBrace(String text) {
                return text.equals("}");
            }
    
            private boolean isControlKeyword(String text) {
                // Add newline before control flow keywords
                return text.matches("\\b(if|else|while|for|return|switch|do|try|catch)\\b");
            }
    
            private boolean isPunctuation(String text) {
                return text.matches("[;.,(){}\\[\\]<>]");
            }
    
            private String getIndentation() {
                return INDENT.repeat(indentLevel);
            }
    
            private String formatToken(String token) {
                // Adjust spacing rules for specific tokens
                if (token.equals("(") || token.equals("[")) return token; // No space before
                if (token.equals(")") || token.equals("]")) return token; // No space after
                if (token.equals("::")) return token;                     // No space around
                return token;
            }
        }.visit(tree);
    }    
}