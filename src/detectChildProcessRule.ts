import * as Lint from 'tslint';
import * as tsutils from 'tsutils';
import * as ts from 'typescript';
import { AstUtils } from './utils/AstUtils';

import { ExtendedMetadata } from './utils/ExtendedMetadata';

const FORBIDDEN_IMPORT_FAILURE_STRING: string = 'Found child_process import';
const FOUND_EXEC_FAILURE_STRING: string = 'Found child_process.exec() with non-literal first argument';

export class Rule extends Lint.Rules.AbstractRule {
    public static metadata: ExtendedMetadata = {
        ruleName: 'detect-child-process',
        type: 'maintainability',
        description: 'Tries to detect instances of child_process',
        options: null, // tslint:disable-line:no-null-keyword
        optionsDescription: '',
        typescriptOnly: true,
        issueClass: 'SDL',
        issueType: 'Error',
        severity: 'Important',
        level: 'Opportunity for Excellence',
        group: 'Security',
        commonWeaknessEnumeration: '88'
    };

    public apply(sourceFile: ts.SourceFile): Lint.RuleFailure[] {
        return this.applyWithFunction(sourceFile, walk);
    }
}

function processImport(
    ctx: Lint.WalkContext<void>,
    node: ts.Node,
    moduleAlias: string | undefined,
    importedFunctionsAliases: string[],
    importedModuleName: string,
    childProcessModuleAliases: Set<string>,
    childProcessFunctionAliases: Set<string>
) {
    if (importedModuleName === 'child_process') {
        ctx.addFailureAt(node.getStart(), node.getWidth(), FORBIDDEN_IMPORT_FAILURE_STRING);
        if (moduleAlias !== undefined) {
            childProcessModuleAliases.add(moduleAlias);
        }
        importedFunctionsAliases.forEach(x => childProcessFunctionAliases.add(x));
    }
}

function walk(ctx: Lint.WalkContext<void>) {
    const childProcessModuleAliases = new Set<string>();
    const childProcessFunctionAliases = new Set<string>();

    function cb(node: ts.Node): void {
        if (tsutils.isImportEqualsDeclaration(node)) {
            const alias: string = node.name.text;

            if (tsutils.isExternalModuleReference(node.moduleReference)) {
                const moduleRef: ts.ExternalModuleReference = node.moduleReference;
                if (tsutils.isStringLiteral(moduleRef.expression)) {
                    const moduleName: string = moduleRef.expression.text;
                    processImport(ctx, node, alias, [], moduleName, childProcessModuleAliases, childProcessFunctionAliases);
                }
            }
        }

        if (tsutils.isImportDeclaration(node)) {
            let alias: string | undefined;
            let importedNames: string[] = [];

            if (node.importClause !== undefined) {
                if (node.importClause.name !== undefined) {
                    alias = tsutils.getIdentifierText(node.importClause.name);
                }
                if (node.importClause.namedBindings !== undefined) {
                    if (tsutils.isNamespaceImport(node.importClause.namedBindings)) {
                        alias = tsutils.getIdentifierText(node.importClause.namedBindings.name);
                    } else if (tsutils.isNamedImports(node.importClause.namedBindings)) {
                        importedNames = node.importClause.namedBindings.elements
                            .filter(x => {
                                let originalIdentifier: ts.Identifier;

                                if (x.propertyName === undefined) {
                                    originalIdentifier = x.name;
                                } else {
                                    originalIdentifier = x.propertyName;
                                }
                                return tsutils.getIdentifierText(originalIdentifier) === 'exec';
                            })
                            .map(x => tsutils.getIdentifierText(x.name));
                    }
                }
            }
            if (tsutils.isStringLiteral(node.moduleSpecifier)) {
                const moduleName: string = node.moduleSpecifier.text;
                processImport(ctx, node, alias, importedNames, moduleName, childProcessModuleAliases, childProcessFunctionAliases);
            }
        }

        if (tsutils.isCallExpression(node)) {
            const functionName: string = AstUtils.getFunctionName(node);
            const functionTarget = AstUtils.getFunctionTarget(node);

            if (functionTarget !== undefined) {
                if (
                    childProcessModuleAliases.has(functionTarget) &&
                    functionName === 'exec' &&
                    node.arguments.length === 1 &&
                    !tsutils.isStringLiteral(node.arguments[0])
                ) {
                    ctx.addFailureAt(node.getStart(), node.getWidth(), FOUND_EXEC_FAILURE_STRING);
                }
            } else {
                if (
                    childProcessFunctionAliases.has(functionName) &&
                    node.arguments.length === 1 &&
                    !tsutils.isStringLiteral(node.arguments[0])
                ) {
                    ctx.addFailureAt(node.getStart(), node.getWidth(), FOUND_EXEC_FAILURE_STRING);
                }
            }
        }

        return ts.forEachChild(node, cb);
    }

    return ts.forEachChild(ctx.sourceFile, cb);
}
