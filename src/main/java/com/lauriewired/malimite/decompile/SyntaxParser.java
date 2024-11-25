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
    private static final String INDENT = "\t"; // Tab character for indentation

    public SyntaxParser(SQLiteDBHandler dbHandler) {
        this.dbHandler = dbHandler;
    }

    public void setContext(String functionName, String className) {
        this.currentFunction = functionName;
        this.currentClass = className;
    }

    public String parseAndFormatCode(String code) {
        try {
            // Clean up the input code first
            code = cleanInputCode(code);
            
            System.out.println("Code: " + code);
            CharStream input = CharStreams.fromString(code);
            lexer = new CPP14Lexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            parser = new CPP14Parser(tokens);
            
            ParseTree tree = parser.translationUnit();
            if (tree == null) {
                LOGGER.warning("Failed to parse code");
                return code;
            }
            
            return new FormattingVisitor().visit(tree);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error parsing code", e);
            return code;
        }
    }

    public void collectCrossReferences(String formattedCode) {
        if (dbHandler == null || currentFunction == null || currentClass == null) {
            LOGGER.warning("Cannot collect cross-references: missing context or database handler");
            return;
        }

        try {
            CharStream input = CharStreams.fromString(formattedCode);
            lexer = new CPP14Lexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            parser = new CPP14Parser(tokens);
            
            ParseTree tree = parser.translationUnit();
            if (tree == null) {
                LOGGER.warning("Failed to parse code for cross-references");
                return;
            }
            
            new CrossReferenceVisitor().visit(tree);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error collecting cross-references", e);
        }
    }

    private class CrossReferenceVisitor extends CPP14ParserBaseVisitor<Void> {
        @Override
        public Void visitPostfixExpression(CPP14Parser.PostfixExpressionContext ctx) {
            // Only handle function calls
            if (ctx.getChildCount() >= 2 && ctx.getChild(1).getText().equals("(")) {
                String calledFunction = ctx.getChild(0).getText();
                String calledClass = null;

                // Extract the class name if it's a method call (contains ::)
                if (calledFunction.contains("::")) {
                    String[] parts = calledFunction.split("::");
                    calledClass = parts[0];
                    calledFunction = parts[1];
                }

                // Store the function reference
                dbHandler.insertFunctionReference(
                    currentFunction,
                    currentClass,
                    calledFunction,
                    calledClass != null ? calledClass : "Unknown",
                    ctx.getStart().getLine()
                );
            }
            return visitChildren(ctx);
        }

        @Override
        public Void visitDeclarationStatement(CPP14Parser.DeclarationStatementContext ctx) {
            if (ctx.blockDeclaration() != null && 
                ctx.blockDeclaration().simpleDeclaration() != null) {
                
                CPP14Parser.SimpleDeclarationContext simpleDecl = 
                    ctx.blockDeclaration().simpleDeclaration();
                
                // Add null check for declSpecifierSeq
                String variableType = "";
                if (simpleDecl.declSpecifierSeq() != null) {
                    variableType = simpleDecl.declSpecifierSeq().getText();
                }
                
                // Process each declarator in the declaration
                if (simpleDecl.initDeclaratorList() != null) {
                    for (CPP14Parser.InitDeclaratorContext initDecl : 
                         simpleDecl.initDeclaratorList().initDeclarator()) {
                        
                        String variableName = initDecl.declarator().getText();
                        // Clean up variable name (remove initialization if present)
                        if (variableName.contains("=")) {
                            variableName = variableName.substring(0, 
                                variableName.indexOf("=")).trim();
                        }

                        // Store the type information
                        dbHandler.insertTypeInformation(
                            variableName,
                            variableType,
                            currentFunction,
                            currentClass,
                            ctx.getStart().getLine()
                        );

                        // Store initial local variable reference
                        dbHandler.insertLocalVariableReference(
                            variableName,
                            currentFunction,
                            currentClass,
                            ctx.getStart().getLine()
                        );
                    }
                }
            }
            return visitChildren(ctx);
        }

        @Override
        public Void visitIdExpression(CPP14Parser.IdExpressionContext ctx) {
            String identifier = ctx.getText();
            
            // Handle class references (contains ::)
            if (identifier.contains("::")) {
                String[] parts = identifier.split("::");
                String referencedClass = parts[0];
                
                // Store class usage reference
                dbHandler.insertFunctionReference(
                    currentFunction,
                    currentClass,
                    null,  // No specific function
                    referencedClass,
                    ctx.getStart().getLine()
                );
            } 
            // Handle local variable references
            else {
                // Check if this identifier is in a function call context
                if (!isPartOfFunctionCall(ctx)) {
                    dbHandler.insertLocalVariableReference(
                        identifier,
                        currentFunction,
                        currentClass,
                        ctx.getStart().getLine()
                    );
                }
            }

            return visitChildren(ctx);
        }

        private boolean isPartOfFunctionCall(CPP14Parser.IdExpressionContext ctx) {
            // Check if this identifier is immediately followed by (
            ParseTree parent = ctx.getParent();
            while (parent != null) {
                if (parent instanceof CPP14Parser.PostfixExpressionContext) {
                    CPP14Parser.PostfixExpressionContext postfix = 
                        (CPP14Parser.PostfixExpressionContext) parent;
                    // Check if this is a function call
                    return postfix.getChildCount() >= 2 && 
                           postfix.getChild(1).getText().equals("(");
                }
                parent = parent.getParent();
            }
            return false;
        }
    }

    private class FormattingVisitor extends CPP14ParserBaseVisitor<String> {
        private int indentLevel = 0;
    
        @Override
        public String visitChildren(RuleNode node) {
            StringBuilder result = new StringBuilder();
            int n = node.getChildCount();
    
            for (int i = 0; i < n; i++) {
                ParseTree child = node.getChild(i);
                String childResult = child.accept(this);
    
                if (childResult != null) {
                    if (isOpeningBrace(childResult)) {
                        result.append(" {\n").append(getIndentation());
                        indentLevel++;
                    } else if (isClosingBrace(childResult)) {
                        result.append("\n");
                        indentLevel--;
                        result.append(getIndentation()).append("}");
                    } else if (isControlKeyword(childResult)) {
                        result.append("\n").append(getIndentation()).append(childResult).append(" ");
                    } else if (needsNewline(childResult)) {
                        result.append(childResult).append("\n").append(getIndentation());
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
            // Ignore EOF token
            if (node.getSymbol().getType() == Token.EOF) {
                return "";
            }
            return formatToken(node.getText());
        }
    
        private boolean needsNewline(String text) {
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
            // Remove <EOF> if present
            if (token.endsWith("<EOF>")) {
                token = token.substring(0, token.length() - 5);
            }

            // Remove spaces in pointer/reference types like "char *" -> "char*"
            if (token.matches("[*|&];")) {
                return token;
            }

            // Adjust spacing rules for specific tokens
            if (token.equals("(") || token.equals("[")) return token;
            if (token.equals(")") || token.equals("]")) return token;
            if (token.equals("::")) return token;
            return token.trim();
        }
    }    

    // Add this new private method
    private String cleanInputCode(String code) {
        return code
            // Replace multiple spaces with a single space
            .replaceAll("\\s+", " ")
            // Remove spaces around operators and punctuation
            .replaceAll("\\s*([{}\\[\\]().,;:><+=\\-*/%&|^!])\\s*", "$1")
            // Add single space after commas
            .replaceAll(",", ", ")
            // Clean up pointer/reference declarations
            .replaceAll("\\s*([*&])\\s*", "$1")
            // Ensure single space around keywords
            .replaceAll("\\b(if|else|while|for|return|switch|do|try|catch)\\b", " $1 ")
            .trim();
    }
}