// Generated from C.g4 by ANTLR 4.13.1
package com.lauriewired.malimite.decompile.antlr;
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link CParser}.
 */
public interface CListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by {@link CParser#primaryExpression}.
	 * @param ctx the parse tree
	 */
	void enterPrimaryExpression(CParser.PrimaryExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#primaryExpression}.
	 * @param ctx the parse tree
	 */
	void exitPrimaryExpression(CParser.PrimaryExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#genericSelection}.
	 * @param ctx the parse tree
	 */
	void enterGenericSelection(CParser.GenericSelectionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#genericSelection}.
	 * @param ctx the parse tree
	 */
	void exitGenericSelection(CParser.GenericSelectionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#genericAssocList}.
	 * @param ctx the parse tree
	 */
	void enterGenericAssocList(CParser.GenericAssocListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#genericAssocList}.
	 * @param ctx the parse tree
	 */
	void exitGenericAssocList(CParser.GenericAssocListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#genericAssociation}.
	 * @param ctx the parse tree
	 */
	void enterGenericAssociation(CParser.GenericAssociationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#genericAssociation}.
	 * @param ctx the parse tree
	 */
	void exitGenericAssociation(CParser.GenericAssociationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#postfixExpression}.
	 * @param ctx the parse tree
	 */
	void enterPostfixExpression(CParser.PostfixExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#postfixExpression}.
	 * @param ctx the parse tree
	 */
	void exitPostfixExpression(CParser.PostfixExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#argumentExpressionList}.
	 * @param ctx the parse tree
	 */
	void enterArgumentExpressionList(CParser.ArgumentExpressionListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#argumentExpressionList}.
	 * @param ctx the parse tree
	 */
	void exitArgumentExpressionList(CParser.ArgumentExpressionListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#unaryExpression}.
	 * @param ctx the parse tree
	 */
	void enterUnaryExpression(CParser.UnaryExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#unaryExpression}.
	 * @param ctx the parse tree
	 */
	void exitUnaryExpression(CParser.UnaryExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#unaryOperator}.
	 * @param ctx the parse tree
	 */
	void enterUnaryOperator(CParser.UnaryOperatorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#unaryOperator}.
	 * @param ctx the parse tree
	 */
	void exitUnaryOperator(CParser.UnaryOperatorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#castExpression}.
	 * @param ctx the parse tree
	 */
	void enterCastExpression(CParser.CastExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#castExpression}.
	 * @param ctx the parse tree
	 */
	void exitCastExpression(CParser.CastExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#multiplicativeExpression}.
	 * @param ctx the parse tree
	 */
	void enterMultiplicativeExpression(CParser.MultiplicativeExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#multiplicativeExpression}.
	 * @param ctx the parse tree
	 */
	void exitMultiplicativeExpression(CParser.MultiplicativeExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#additiveExpression}.
	 * @param ctx the parse tree
	 */
	void enterAdditiveExpression(CParser.AdditiveExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#additiveExpression}.
	 * @param ctx the parse tree
	 */
	void exitAdditiveExpression(CParser.AdditiveExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#shiftExpression}.
	 * @param ctx the parse tree
	 */
	void enterShiftExpression(CParser.ShiftExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#shiftExpression}.
	 * @param ctx the parse tree
	 */
	void exitShiftExpression(CParser.ShiftExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#relationalExpression}.
	 * @param ctx the parse tree
	 */
	void enterRelationalExpression(CParser.RelationalExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#relationalExpression}.
	 * @param ctx the parse tree
	 */
	void exitRelationalExpression(CParser.RelationalExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#equalityExpression}.
	 * @param ctx the parse tree
	 */
	void enterEqualityExpression(CParser.EqualityExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#equalityExpression}.
	 * @param ctx the parse tree
	 */
	void exitEqualityExpression(CParser.EqualityExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#andExpression}.
	 * @param ctx the parse tree
	 */
	void enterAndExpression(CParser.AndExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#andExpression}.
	 * @param ctx the parse tree
	 */
	void exitAndExpression(CParser.AndExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#exclusiveOrExpression}.
	 * @param ctx the parse tree
	 */
	void enterExclusiveOrExpression(CParser.ExclusiveOrExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#exclusiveOrExpression}.
	 * @param ctx the parse tree
	 */
	void exitExclusiveOrExpression(CParser.ExclusiveOrExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#inclusiveOrExpression}.
	 * @param ctx the parse tree
	 */
	void enterInclusiveOrExpression(CParser.InclusiveOrExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#inclusiveOrExpression}.
	 * @param ctx the parse tree
	 */
	void exitInclusiveOrExpression(CParser.InclusiveOrExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#logicalAndExpression}.
	 * @param ctx the parse tree
	 */
	void enterLogicalAndExpression(CParser.LogicalAndExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#logicalAndExpression}.
	 * @param ctx the parse tree
	 */
	void exitLogicalAndExpression(CParser.LogicalAndExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#logicalOrExpression}.
	 * @param ctx the parse tree
	 */
	void enterLogicalOrExpression(CParser.LogicalOrExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#logicalOrExpression}.
	 * @param ctx the parse tree
	 */
	void exitLogicalOrExpression(CParser.LogicalOrExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#conditionalExpression}.
	 * @param ctx the parse tree
	 */
	void enterConditionalExpression(CParser.ConditionalExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#conditionalExpression}.
	 * @param ctx the parse tree
	 */
	void exitConditionalExpression(CParser.ConditionalExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#assignmentExpression}.
	 * @param ctx the parse tree
	 */
	void enterAssignmentExpression(CParser.AssignmentExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#assignmentExpression}.
	 * @param ctx the parse tree
	 */
	void exitAssignmentExpression(CParser.AssignmentExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#assignmentOperator}.
	 * @param ctx the parse tree
	 */
	void enterAssignmentOperator(CParser.AssignmentOperatorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#assignmentOperator}.
	 * @param ctx the parse tree
	 */
	void exitAssignmentOperator(CParser.AssignmentOperatorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#expression}.
	 * @param ctx the parse tree
	 */
	void enterExpression(CParser.ExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#expression}.
	 * @param ctx the parse tree
	 */
	void exitExpression(CParser.ExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#constantExpression}.
	 * @param ctx the parse tree
	 */
	void enterConstantExpression(CParser.ConstantExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#constantExpression}.
	 * @param ctx the parse tree
	 */
	void exitConstantExpression(CParser.ConstantExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#declaration}.
	 * @param ctx the parse tree
	 */
	void enterDeclaration(CParser.DeclarationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#declaration}.
	 * @param ctx the parse tree
	 */
	void exitDeclaration(CParser.DeclarationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#declarationSpecifiers}.
	 * @param ctx the parse tree
	 */
	void enterDeclarationSpecifiers(CParser.DeclarationSpecifiersContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#declarationSpecifiers}.
	 * @param ctx the parse tree
	 */
	void exitDeclarationSpecifiers(CParser.DeclarationSpecifiersContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#declarationSpecifiers2}.
	 * @param ctx the parse tree
	 */
	void enterDeclarationSpecifiers2(CParser.DeclarationSpecifiers2Context ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#declarationSpecifiers2}.
	 * @param ctx the parse tree
	 */
	void exitDeclarationSpecifiers2(CParser.DeclarationSpecifiers2Context ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#declarationSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterDeclarationSpecifier(CParser.DeclarationSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#declarationSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitDeclarationSpecifier(CParser.DeclarationSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#initDeclaratorList}.
	 * @param ctx the parse tree
	 */
	void enterInitDeclaratorList(CParser.InitDeclaratorListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#initDeclaratorList}.
	 * @param ctx the parse tree
	 */
	void exitInitDeclaratorList(CParser.InitDeclaratorListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#initDeclarator}.
	 * @param ctx the parse tree
	 */
	void enterInitDeclarator(CParser.InitDeclaratorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#initDeclarator}.
	 * @param ctx the parse tree
	 */
	void exitInitDeclarator(CParser.InitDeclaratorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#storageClassSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterStorageClassSpecifier(CParser.StorageClassSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#storageClassSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitStorageClassSpecifier(CParser.StorageClassSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#typeSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterTypeSpecifier(CParser.TypeSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#typeSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitTypeSpecifier(CParser.TypeSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#structOrUnionSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterStructOrUnionSpecifier(CParser.StructOrUnionSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#structOrUnionSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitStructOrUnionSpecifier(CParser.StructOrUnionSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#structOrUnion}.
	 * @param ctx the parse tree
	 */
	void enterStructOrUnion(CParser.StructOrUnionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#structOrUnion}.
	 * @param ctx the parse tree
	 */
	void exitStructOrUnion(CParser.StructOrUnionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#structDeclarationList}.
	 * @param ctx the parse tree
	 */
	void enterStructDeclarationList(CParser.StructDeclarationListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#structDeclarationList}.
	 * @param ctx the parse tree
	 */
	void exitStructDeclarationList(CParser.StructDeclarationListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#structDeclaration}.
	 * @param ctx the parse tree
	 */
	void enterStructDeclaration(CParser.StructDeclarationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#structDeclaration}.
	 * @param ctx the parse tree
	 */
	void exitStructDeclaration(CParser.StructDeclarationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#specifierQualifierList}.
	 * @param ctx the parse tree
	 */
	void enterSpecifierQualifierList(CParser.SpecifierQualifierListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#specifierQualifierList}.
	 * @param ctx the parse tree
	 */
	void exitSpecifierQualifierList(CParser.SpecifierQualifierListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#structDeclaratorList}.
	 * @param ctx the parse tree
	 */
	void enterStructDeclaratorList(CParser.StructDeclaratorListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#structDeclaratorList}.
	 * @param ctx the parse tree
	 */
	void exitStructDeclaratorList(CParser.StructDeclaratorListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#structDeclarator}.
	 * @param ctx the parse tree
	 */
	void enterStructDeclarator(CParser.StructDeclaratorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#structDeclarator}.
	 * @param ctx the parse tree
	 */
	void exitStructDeclarator(CParser.StructDeclaratorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#enumSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterEnumSpecifier(CParser.EnumSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#enumSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitEnumSpecifier(CParser.EnumSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#enumeratorList}.
	 * @param ctx the parse tree
	 */
	void enterEnumeratorList(CParser.EnumeratorListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#enumeratorList}.
	 * @param ctx the parse tree
	 */
	void exitEnumeratorList(CParser.EnumeratorListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#enumerator}.
	 * @param ctx the parse tree
	 */
	void enterEnumerator(CParser.EnumeratorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#enumerator}.
	 * @param ctx the parse tree
	 */
	void exitEnumerator(CParser.EnumeratorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#enumerationConstant}.
	 * @param ctx the parse tree
	 */
	void enterEnumerationConstant(CParser.EnumerationConstantContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#enumerationConstant}.
	 * @param ctx the parse tree
	 */
	void exitEnumerationConstant(CParser.EnumerationConstantContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#atomicTypeSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterAtomicTypeSpecifier(CParser.AtomicTypeSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#atomicTypeSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitAtomicTypeSpecifier(CParser.AtomicTypeSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#typeQualifier}.
	 * @param ctx the parse tree
	 */
	void enterTypeQualifier(CParser.TypeQualifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#typeQualifier}.
	 * @param ctx the parse tree
	 */
	void exitTypeQualifier(CParser.TypeQualifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#functionSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterFunctionSpecifier(CParser.FunctionSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#functionSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitFunctionSpecifier(CParser.FunctionSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#alignmentSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterAlignmentSpecifier(CParser.AlignmentSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#alignmentSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitAlignmentSpecifier(CParser.AlignmentSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#declarator}.
	 * @param ctx the parse tree
	 */
	void enterDeclarator(CParser.DeclaratorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#declarator}.
	 * @param ctx the parse tree
	 */
	void exitDeclarator(CParser.DeclaratorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#directDeclarator}.
	 * @param ctx the parse tree
	 */
	void enterDirectDeclarator(CParser.DirectDeclaratorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#directDeclarator}.
	 * @param ctx the parse tree
	 */
	void exitDirectDeclarator(CParser.DirectDeclaratorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#vcSpecificModifer}.
	 * @param ctx the parse tree
	 */
	void enterVcSpecificModifer(CParser.VcSpecificModiferContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#vcSpecificModifer}.
	 * @param ctx the parse tree
	 */
	void exitVcSpecificModifer(CParser.VcSpecificModiferContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#gccDeclaratorExtension}.
	 * @param ctx the parse tree
	 */
	void enterGccDeclaratorExtension(CParser.GccDeclaratorExtensionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#gccDeclaratorExtension}.
	 * @param ctx the parse tree
	 */
	void exitGccDeclaratorExtension(CParser.GccDeclaratorExtensionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#gccAttributeSpecifier}.
	 * @param ctx the parse tree
	 */
	void enterGccAttributeSpecifier(CParser.GccAttributeSpecifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#gccAttributeSpecifier}.
	 * @param ctx the parse tree
	 */
	void exitGccAttributeSpecifier(CParser.GccAttributeSpecifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#gccAttributeList}.
	 * @param ctx the parse tree
	 */
	void enterGccAttributeList(CParser.GccAttributeListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#gccAttributeList}.
	 * @param ctx the parse tree
	 */
	void exitGccAttributeList(CParser.GccAttributeListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#gccAttribute}.
	 * @param ctx the parse tree
	 */
	void enterGccAttribute(CParser.GccAttributeContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#gccAttribute}.
	 * @param ctx the parse tree
	 */
	void exitGccAttribute(CParser.GccAttributeContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#nestedParenthesesBlock}.
	 * @param ctx the parse tree
	 */
	void enterNestedParenthesesBlock(CParser.NestedParenthesesBlockContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#nestedParenthesesBlock}.
	 * @param ctx the parse tree
	 */
	void exitNestedParenthesesBlock(CParser.NestedParenthesesBlockContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#pointer}.
	 * @param ctx the parse tree
	 */
	void enterPointer(CParser.PointerContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#pointer}.
	 * @param ctx the parse tree
	 */
	void exitPointer(CParser.PointerContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#typeQualifierList}.
	 * @param ctx the parse tree
	 */
	void enterTypeQualifierList(CParser.TypeQualifierListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#typeQualifierList}.
	 * @param ctx the parse tree
	 */
	void exitTypeQualifierList(CParser.TypeQualifierListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#parameterTypeList}.
	 * @param ctx the parse tree
	 */
	void enterParameterTypeList(CParser.ParameterTypeListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#parameterTypeList}.
	 * @param ctx the parse tree
	 */
	void exitParameterTypeList(CParser.ParameterTypeListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#parameterList}.
	 * @param ctx the parse tree
	 */
	void enterParameterList(CParser.ParameterListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#parameterList}.
	 * @param ctx the parse tree
	 */
	void exitParameterList(CParser.ParameterListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#parameterDeclaration}.
	 * @param ctx the parse tree
	 */
	void enterParameterDeclaration(CParser.ParameterDeclarationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#parameterDeclaration}.
	 * @param ctx the parse tree
	 */
	void exitParameterDeclaration(CParser.ParameterDeclarationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#identifierList}.
	 * @param ctx the parse tree
	 */
	void enterIdentifierList(CParser.IdentifierListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#identifierList}.
	 * @param ctx the parse tree
	 */
	void exitIdentifierList(CParser.IdentifierListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#typeName}.
	 * @param ctx the parse tree
	 */
	void enterTypeName(CParser.TypeNameContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#typeName}.
	 * @param ctx the parse tree
	 */
	void exitTypeName(CParser.TypeNameContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#abstractDeclarator}.
	 * @param ctx the parse tree
	 */
	void enterAbstractDeclarator(CParser.AbstractDeclaratorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#abstractDeclarator}.
	 * @param ctx the parse tree
	 */
	void exitAbstractDeclarator(CParser.AbstractDeclaratorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#directAbstractDeclarator}.
	 * @param ctx the parse tree
	 */
	void enterDirectAbstractDeclarator(CParser.DirectAbstractDeclaratorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#directAbstractDeclarator}.
	 * @param ctx the parse tree
	 */
	void exitDirectAbstractDeclarator(CParser.DirectAbstractDeclaratorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#typedefName}.
	 * @param ctx the parse tree
	 */
	void enterTypedefName(CParser.TypedefNameContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#typedefName}.
	 * @param ctx the parse tree
	 */
	void exitTypedefName(CParser.TypedefNameContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#initializer}.
	 * @param ctx the parse tree
	 */
	void enterInitializer(CParser.InitializerContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#initializer}.
	 * @param ctx the parse tree
	 */
	void exitInitializer(CParser.InitializerContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#initializerList}.
	 * @param ctx the parse tree
	 */
	void enterInitializerList(CParser.InitializerListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#initializerList}.
	 * @param ctx the parse tree
	 */
	void exitInitializerList(CParser.InitializerListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#designation}.
	 * @param ctx the parse tree
	 */
	void enterDesignation(CParser.DesignationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#designation}.
	 * @param ctx the parse tree
	 */
	void exitDesignation(CParser.DesignationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#designatorList}.
	 * @param ctx the parse tree
	 */
	void enterDesignatorList(CParser.DesignatorListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#designatorList}.
	 * @param ctx the parse tree
	 */
	void exitDesignatorList(CParser.DesignatorListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#designator}.
	 * @param ctx the parse tree
	 */
	void enterDesignator(CParser.DesignatorContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#designator}.
	 * @param ctx the parse tree
	 */
	void exitDesignator(CParser.DesignatorContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#staticAssertDeclaration}.
	 * @param ctx the parse tree
	 */
	void enterStaticAssertDeclaration(CParser.StaticAssertDeclarationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#staticAssertDeclaration}.
	 * @param ctx the parse tree
	 */
	void exitStaticAssertDeclaration(CParser.StaticAssertDeclarationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#statement}.
	 * @param ctx the parse tree
	 */
	void enterStatement(CParser.StatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#statement}.
	 * @param ctx the parse tree
	 */
	void exitStatement(CParser.StatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#labeledStatement}.
	 * @param ctx the parse tree
	 */
	void enterLabeledStatement(CParser.LabeledStatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#labeledStatement}.
	 * @param ctx the parse tree
	 */
	void exitLabeledStatement(CParser.LabeledStatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#compoundStatement}.
	 * @param ctx the parse tree
	 */
	void enterCompoundStatement(CParser.CompoundStatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#compoundStatement}.
	 * @param ctx the parse tree
	 */
	void exitCompoundStatement(CParser.CompoundStatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#blockItemList}.
	 * @param ctx the parse tree
	 */
	void enterBlockItemList(CParser.BlockItemListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#blockItemList}.
	 * @param ctx the parse tree
	 */
	void exitBlockItemList(CParser.BlockItemListContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#blockItem}.
	 * @param ctx the parse tree
	 */
	void enterBlockItem(CParser.BlockItemContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#blockItem}.
	 * @param ctx the parse tree
	 */
	void exitBlockItem(CParser.BlockItemContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#expressionStatement}.
	 * @param ctx the parse tree
	 */
	void enterExpressionStatement(CParser.ExpressionStatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#expressionStatement}.
	 * @param ctx the parse tree
	 */
	void exitExpressionStatement(CParser.ExpressionStatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#selectionStatement}.
	 * @param ctx the parse tree
	 */
	void enterSelectionStatement(CParser.SelectionStatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#selectionStatement}.
	 * @param ctx the parse tree
	 */
	void exitSelectionStatement(CParser.SelectionStatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#iterationStatement}.
	 * @param ctx the parse tree
	 */
	void enterIterationStatement(CParser.IterationStatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#iterationStatement}.
	 * @param ctx the parse tree
	 */
	void exitIterationStatement(CParser.IterationStatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#forCondition}.
	 * @param ctx the parse tree
	 */
	void enterForCondition(CParser.ForConditionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#forCondition}.
	 * @param ctx the parse tree
	 */
	void exitForCondition(CParser.ForConditionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#forDeclaration}.
	 * @param ctx the parse tree
	 */
	void enterForDeclaration(CParser.ForDeclarationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#forDeclaration}.
	 * @param ctx the parse tree
	 */
	void exitForDeclaration(CParser.ForDeclarationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#forExpression}.
	 * @param ctx the parse tree
	 */
	void enterForExpression(CParser.ForExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#forExpression}.
	 * @param ctx the parse tree
	 */
	void exitForExpression(CParser.ForExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#jumpStatement}.
	 * @param ctx the parse tree
	 */
	void enterJumpStatement(CParser.JumpStatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#jumpStatement}.
	 * @param ctx the parse tree
	 */
	void exitJumpStatement(CParser.JumpStatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#compilationUnit}.
	 * @param ctx the parse tree
	 */
	void enterCompilationUnit(CParser.CompilationUnitContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#compilationUnit}.
	 * @param ctx the parse tree
	 */
	void exitCompilationUnit(CParser.CompilationUnitContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#translationUnit}.
	 * @param ctx the parse tree
	 */
	void enterTranslationUnit(CParser.TranslationUnitContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#translationUnit}.
	 * @param ctx the parse tree
	 */
	void exitTranslationUnit(CParser.TranslationUnitContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#externalDeclaration}.
	 * @param ctx the parse tree
	 */
	void enterExternalDeclaration(CParser.ExternalDeclarationContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#externalDeclaration}.
	 * @param ctx the parse tree
	 */
	void exitExternalDeclaration(CParser.ExternalDeclarationContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#functionDefinition}.
	 * @param ctx the parse tree
	 */
	void enterFunctionDefinition(CParser.FunctionDefinitionContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#functionDefinition}.
	 * @param ctx the parse tree
	 */
	void exitFunctionDefinition(CParser.FunctionDefinitionContext ctx);
	/**
	 * Enter a parse tree produced by {@link CParser#declarationList}.
	 * @param ctx the parse tree
	 */
	void enterDeclarationList(CParser.DeclarationListContext ctx);
	/**
	 * Exit a parse tree produced by {@link CParser#declarationList}.
	 * @param ctx the parse tree
	 */
	void exitDeclarationList(CParser.DeclarationListContext ctx);
}