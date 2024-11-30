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
    private CPP14Lexer lexer = new CPP14Lexer(null);
    private CPP14Parser parser = new CPP14Parser(new CommonTokenStream(lexer));
    private static final Logger LOGGER = Logger.getLogger(SyntaxParser.class.getName());
    private SQLiteDBHandler dbHandler;
    private String currentFunction;
    private String currentClass;
    private String formattedCode;

    public SyntaxParser(SQLiteDBHandler dbHandler) {
        this.dbHandler = dbHandler;
        lexer.removeErrorListeners();
        parser.removeErrorListeners();
    }

    public void setContext(String functionName, String className) {
        this.currentFunction = functionName;
        this.currentClass = className;
    }

    public String parseAndFormatCode(String code) {
        try {            
            CharStream input = CharStreams.fromString(code);
            lexer.setInputStream(input);
            
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            parser.setTokenStream(tokens);
            
            // Temporarily return unformatted code while testing performance
            return code;
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

        this.formattedCode = formattedCode;
        try {
            CharStream input = CharStreams.fromString(formattedCode);
            lexer.setInputStream(input);
            
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            parser.setTokenStream(tokens);
            
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
        private int commentLineAdjustment = 0;

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

                // Calculate adjusted line number
                int actualLine = calculateActualLineNumber(ctx.getStart().getLine());

                // Store the function reference with adjusted line number
                dbHandler.insertFunctionReference(
                    currentFunction,
                    currentClass,
                    calledFunction,
                    calledClass != null ? calledClass : "Unknown",
                    actualLine
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

                        // Use adjusted line numbers when storing references
                        int actualLine = calculateActualLineNumber(ctx.getStart().getLine());
                        
                        // Store the type information
                        dbHandler.insertTypeInformation(
                            variableName,
                            variableType,
                            currentFunction,
                            currentClass,
                            actualLine
                        );

                        // Store initial local variable reference
                        dbHandler.insertLocalVariableReference(
                            variableName,
                            currentFunction,
                            currentClass,
                            actualLine
                        );
                    }
                }
            }
            return visitChildren(ctx);
        }

        @Override
        public Void visitIdExpression(CPP14Parser.IdExpressionContext ctx) {
            String identifier = ctx.getText();
            
            // Use adjusted line numbers
            int actualLine = calculateActualLineNumber(ctx.getStart().getLine());
            
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
                    actualLine
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
                        actualLine
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

        private int calculateActualLineNumber(int parsedLineNumber) {
            // Count actual code lines up to the parsed line number
            String[] lines = formattedCode.split("\n", parsedLineNumber + 1);
            int actualLineNumber = 0;
            
            for (int i = 0; i < Math.min(lines.length, parsedLineNumber); i++) {
                actualLineNumber++; // Every line, including empty ones and comments, counts
                String line = lines[i].trim();
                
                // For multi-line comments, add the additional lines
                if (line.contains("/*")) {
                    int currentLine = i;
                    while (currentLine < lines.length && !lines[currentLine].contains("*/")) {
                        if (currentLine != i) { // Don't double-count the first line
                            actualLineNumber++;
                        }
                        currentLine++;
                    }
                    if (currentLine < lines.length && lines[currentLine].contains("*/")) {
                        if (currentLine != i) { // Don't double-count if comment ends on same line
                            actualLineNumber++;
                        }
                    }
                    i = currentLine;
                }
            }
            
            return actualLineNumber;
        }
    }
}