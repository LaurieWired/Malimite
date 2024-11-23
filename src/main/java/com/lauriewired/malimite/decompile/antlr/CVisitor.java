// Generated from C.g4 by ANTLR 4.13.1
package com.lauriewired.malimite.decompile.antlr;
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link CParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface CVisitor<T> extends ParseTreeVisitor<T> {
	/**
	 * Visit a parse tree produced by {@link CParser#primaryExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPrimaryExpression(CParser.PrimaryExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#genericSelection}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGenericSelection(CParser.GenericSelectionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#genericAssocList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGenericAssocList(CParser.GenericAssocListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#genericAssociation}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGenericAssociation(CParser.GenericAssociationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#postfixExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPostfixExpression(CParser.PostfixExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#argumentExpressionList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArgumentExpressionList(CParser.ArgumentExpressionListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#unaryExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitUnaryExpression(CParser.UnaryExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#unaryOperator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitUnaryOperator(CParser.UnaryOperatorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#castExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCastExpression(CParser.CastExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#multiplicativeExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitMultiplicativeExpression(CParser.MultiplicativeExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#additiveExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAdditiveExpression(CParser.AdditiveExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#shiftExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitShiftExpression(CParser.ShiftExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#relationalExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRelationalExpression(CParser.RelationalExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#equalityExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEqualityExpression(CParser.EqualityExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#andExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAndExpression(CParser.AndExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#exclusiveOrExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitExclusiveOrExpression(CParser.ExclusiveOrExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#inclusiveOrExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInclusiveOrExpression(CParser.InclusiveOrExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#logicalAndExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLogicalAndExpression(CParser.LogicalAndExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#logicalOrExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLogicalOrExpression(CParser.LogicalOrExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#conditionalExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitConditionalExpression(CParser.ConditionalExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#assignmentExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAssignmentExpression(CParser.AssignmentExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#assignmentOperator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAssignmentOperator(CParser.AssignmentOperatorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#expression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitExpression(CParser.ExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#constantExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitConstantExpression(CParser.ConstantExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#declaration}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDeclaration(CParser.DeclarationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#declarationSpecifiers}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDeclarationSpecifiers(CParser.DeclarationSpecifiersContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#declarationSpecifiers2}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDeclarationSpecifiers2(CParser.DeclarationSpecifiers2Context ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#declarationSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDeclarationSpecifier(CParser.DeclarationSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#initDeclaratorList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInitDeclaratorList(CParser.InitDeclaratorListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#initDeclarator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInitDeclarator(CParser.InitDeclaratorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#storageClassSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStorageClassSpecifier(CParser.StorageClassSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#typeSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTypeSpecifier(CParser.TypeSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#structOrUnionSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStructOrUnionSpecifier(CParser.StructOrUnionSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#structOrUnion}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStructOrUnion(CParser.StructOrUnionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#structDeclarationList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStructDeclarationList(CParser.StructDeclarationListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#structDeclaration}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStructDeclaration(CParser.StructDeclarationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#specifierQualifierList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSpecifierQualifierList(CParser.SpecifierQualifierListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#structDeclaratorList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStructDeclaratorList(CParser.StructDeclaratorListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#structDeclarator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStructDeclarator(CParser.StructDeclaratorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#enumSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEnumSpecifier(CParser.EnumSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#enumeratorList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEnumeratorList(CParser.EnumeratorListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#enumerator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEnumerator(CParser.EnumeratorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#enumerationConstant}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEnumerationConstant(CParser.EnumerationConstantContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#atomicTypeSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAtomicTypeSpecifier(CParser.AtomicTypeSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#typeQualifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTypeQualifier(CParser.TypeQualifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#functionSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitFunctionSpecifier(CParser.FunctionSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#alignmentSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAlignmentSpecifier(CParser.AlignmentSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#declarator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDeclarator(CParser.DeclaratorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#directDeclarator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDirectDeclarator(CParser.DirectDeclaratorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#vcSpecificModifer}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitVcSpecificModifer(CParser.VcSpecificModiferContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#gccDeclaratorExtension}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGccDeclaratorExtension(CParser.GccDeclaratorExtensionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#gccAttributeSpecifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGccAttributeSpecifier(CParser.GccAttributeSpecifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#gccAttributeList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGccAttributeList(CParser.GccAttributeListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#gccAttribute}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGccAttribute(CParser.GccAttributeContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#nestedParenthesesBlock}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitNestedParenthesesBlock(CParser.NestedParenthesesBlockContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#pointer}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPointer(CParser.PointerContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#typeQualifierList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTypeQualifierList(CParser.TypeQualifierListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#parameterTypeList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitParameterTypeList(CParser.ParameterTypeListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#parameterList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitParameterList(CParser.ParameterListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#parameterDeclaration}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitParameterDeclaration(CParser.ParameterDeclarationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#identifierList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitIdentifierList(CParser.IdentifierListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#typeName}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTypeName(CParser.TypeNameContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#abstractDeclarator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAbstractDeclarator(CParser.AbstractDeclaratorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#directAbstractDeclarator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDirectAbstractDeclarator(CParser.DirectAbstractDeclaratorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#typedefName}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTypedefName(CParser.TypedefNameContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#initializer}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInitializer(CParser.InitializerContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#initializerList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInitializerList(CParser.InitializerListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#designation}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDesignation(CParser.DesignationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#designatorList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDesignatorList(CParser.DesignatorListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#designator}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDesignator(CParser.DesignatorContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#staticAssertDeclaration}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStaticAssertDeclaration(CParser.StaticAssertDeclarationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#statement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStatement(CParser.StatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#labeledStatement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLabeledStatement(CParser.LabeledStatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#compoundStatement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCompoundStatement(CParser.CompoundStatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#blockItemList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitBlockItemList(CParser.BlockItemListContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#blockItem}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitBlockItem(CParser.BlockItemContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#expressionStatement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitExpressionStatement(CParser.ExpressionStatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#selectionStatement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSelectionStatement(CParser.SelectionStatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#iterationStatement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitIterationStatement(CParser.IterationStatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#forCondition}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitForCondition(CParser.ForConditionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#forDeclaration}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitForDeclaration(CParser.ForDeclarationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#forExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitForExpression(CParser.ForExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#jumpStatement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitJumpStatement(CParser.JumpStatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#compilationUnit}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCompilationUnit(CParser.CompilationUnitContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#translationUnit}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTranslationUnit(CParser.TranslationUnitContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#externalDeclaration}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitExternalDeclaration(CParser.ExternalDeclarationContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#functionDefinition}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitFunctionDefinition(CParser.FunctionDefinitionContext ctx);
	/**
	 * Visit a parse tree produced by {@link CParser#declarationList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDeclarationList(CParser.DeclarationListContext ctx);
}