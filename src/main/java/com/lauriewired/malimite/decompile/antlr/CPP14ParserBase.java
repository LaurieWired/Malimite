package com.lauriewired.malimite.decompile.antlr;

import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.TokenStream;

public abstract class CPP14ParserBase extends Parser {
    public CPP14ParserBase(TokenStream input) {
        super(input);
    }

    // Stub implementation for IsPureSpecifierAllowed
    public boolean IsPureSpecifierAllowed() {
        return true;
    }
}
