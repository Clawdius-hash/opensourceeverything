/**
 * LanguageProfile — the interface that separates what the mapper KNOWS
 * (how to build graphs from code) from what it ASSUMES (that the code is JavaScript).
 *
 * The mapper's logic is universal. The vocabulary is language-specific.
 * This interface IS the vocabulary.
 *
 * Every field answers one question: "How does THIS language express THIS concept?"
 * The mapper asks the profile instead of hardcoding the answer.
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { NodeType, SemanticSentence } from './types.js';
import type { CalleePattern } from './calleePatterns.js';
import type { ScopeType, VariableInfo } from './mapper.js';

// ─── Resolved callee from a call expression ────────────────────────────

export interface ResolvedCalleeResult {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
  chain: string[];
}

// ─── Resolved property access (non-call member expression) ─────────────

export interface ResolvedPropertyResult {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// ─── Structural analysis result ────────────────────────────────────────

export interface StructuralAnalysisResult {
  middlewareNames: string[];
  hasAuthGate: boolean;
  hasRateLimiter: boolean;
  hasCsrfProtection: boolean;
  hasValidation: boolean;
  routePath: string | null;
  httpMethod: string | null;
}

// ─── The Profile ───────────────────────────────────────────────────────

export interface LanguageProfile {
  /** Language identifier — 'javascript', 'python', 'go', etc. */
  id: string;

  /** File extensions this profile handles */
  extensions: string[];

  // ═══════════════════════════════════════════════════════════════════════
  // Layer 1: AST Node Type Recognition
  // "What IS this node?"
  // ═══════════════════════════════════════════════════════════════════════

  /** Node types that create a function scope */
  functionScopeTypes: ReadonlySet<string>;

  /** Node types that create a block scope */
  blockScopeTypes: ReadonlySet<string>;

  /** Node types that create a class scope */
  classScopeTypes: ReadonlySet<string>;

  /**
   * Determine the scope type for a given AST node.
   * Returns null if the node doesn't create a new scope.
   */
  getScopeType: (node: SyntaxNode) => ScopeType | null;

  /**
   * Node types that represent variable declarations.
   * JS: ['lexical_declaration', 'variable_declaration']
   * Python: ['assignment', 'augmented_assignment']
   * Go: ['short_var_declaration', 'var_declaration']
   */
  variableDeclarationTypes: ReadonlySet<string>;

  /**
   * Node types that represent function declarations (for hoisting/registration).
   * JS: ['function_declaration']
   * Python: ['function_definition']
   * Go: ['function_declaration', 'method_declaration']
   */
  functionDeclarationTypes: ReadonlySet<string>;

  // ═══════════════════════════════════════════════════════════════════════
  // Layer 2: AST Child Access
  // "How do I extract data FROM this node?"
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Process a variable declaration node: extract and declare variables
   * in the current scope with taint and producing node info.
   * This replaces processVariableDeclaration() in the mapper.
   */
  processVariableDeclaration: (node: SyntaxNode, ctx: MapperContextLike) => void;

  /**
   * Process function parameters: declare params in the current scope.
   * This replaces processFunctionParams() in the mapper.
   */
  processFunctionParams: (funcNode: SyntaxNode, ctx: MapperContextLike) => void;

  /**
   * Extract variable names from destructuring patterns.
   * This replaces extractPatternNames() in the mapper.
   */
  extractPatternNames: (pattern: SyntaxNode) => string[];

  // ═══════════════════════════════════════════════════════════════════════
  // Layer 3: Callee Resolution (Phoneme Dictionary)
  // "What does this call MEAN?"
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Resolve a call expression node to a NeuralMap node type.
   * Wraps resolveCallee() — chain extraction + pattern lookup.
   */
  resolveCallee: (node: SyntaxNode) => ResolvedCalleeResult | null;

  /**
   * Resolve a property access (member_expression) to a NeuralMap node type.
   * For standalone property access like req.body, process.env.
   */
  resolvePropertyAccess: (node: SyntaxNode) => ResolvedPropertyResult | null;

  /**
   * Look up a callee chain in the phoneme dictionary.
   * This is the raw lookup — profile.resolveCallee uses this internally
   * but the mapper also needs it for computed property resolution and alias chains.
   */
  lookupCallee: (chain: string[]) => CalleePattern | null;

  /**
   * Analyze structural patterns (middleware chains, route definitions).
   * Returns null if no structural pattern matches.
   */
  analyzeStructure: (node: SyntaxNode) => StructuralAnalysisResult | null;

  // ═══════════════════════════════════════════════════════════════════════
  // Layer 4: Taint Source Detection
  // "What is user input in this language?"
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Inline taint source pattern — matches code snapshots that contain
   * known tainted property accesses (req.body, req.query, etc.)
   * Used for inter-procedural taint detection in code_snapshot strings.
   */
  ingressPattern: RegExp;

  /**
   * Tainted object paths that indicate HTTP request data.
   * Used by resolvePropertyAccess to classify member expressions.
   */
  taintedPaths: ReadonlySet<string>;

  // ═══════════════════════════════════════════════════════════════════════
  // Layer 5: Node Classification
  // "How does the walker classify each AST node type?"
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * The walker classification — the heart of the switch statement.
   * Given an AST node, returns classification info or null if unrecognized.
   *
   * This method handles all node types that the main walkWithScopes switch
   * would match: call_expression, function_declaration, if_statement, etc.
   *
   * It does NOT handle:
   * - Scope push/pop (the mapper does that via getScopeType)
   * - Variable declarations (the mapper does that via processVariableDeclaration)
   * - Recursive child walking (the mapper does that)
   * - Post-walk taint propagation (the mapper does that)
   *
   * It DOES handle:
   * - Creating NeuralMapNodes for classified node types
   * - Setting up data flow edges for call arguments
   * - Registering functions in the function registry
   * - Registering pending calls
   * - Callback parameter taint setup
   */
  classifyNode: (node: SyntaxNode, ctx: MapperContextLike) => void;

  /**
   * Extract taint sources from an expression tree.
   * Replaces extractTaintSources() — walks expression nodes recursively
   * to find every tainted leaf.
   */
  extractTaintSources: (expr: SyntaxNode, ctx: MapperContextLike) => TaintSourceResult[];

  /**
   * Post-visit hook for functions — check if return expression is tainted.
   * Called after walking a function's body.
   */
  postVisitFunction?: (node: SyntaxNode, ctx: MapperContextLike) => void;

  /**
   * Pre-visit hook for iteration statements — set up loop variable taint.
   * Called before walking a for-of/for-in body.
   */
  preVisitIteration?: (node: SyntaxNode, ctx: MapperContextLike) => void;

  /**
   * Post-visit hook for iteration — re-mark loop variable taint.
   */
  postVisitIteration?: (node: SyntaxNode, ctx: MapperContextLike) => void;

  /**
   * Check if a node type is a "value-first" declaration that needs
   * children walked before the declaration is processed.
   * JS: lexical_declaration, variable_declaration
   */
  isValueFirstDeclaration: (nodeType: string) => boolean;

  /**
   * Check if a node is a statement container (for lastCreatedNodeId clearing).
   * JS: 'program', 'statement_block'
   */
  isStatementContainer: (nodeType: string) => boolean;

  /**
   * Optional regex to extract function parameter strings from code_snapshot.
   * Used by propagateInterproceduralTaint to find param names from
   * STRUCTURAL node code_snapshots in a language-agnostic way.
   *
   * The regex should capture the full parameter list in group 1.
   * The mapper splits on commas and strips type annotations, defaults, and
   * splat prefixes (*, **, ...) to get plain param names.
   *
   * JS default (built-in): function name(params) | (params) => | name(params) {
   * Python: def name(params):
   */
  functionParamPattern?: RegExp;

  /**
   * Optional: evaluate a condition expression for dead-branch elimination.
   * Returns true/false if the condition can be statically resolved, or null if unknown.
   * Used by walkWithScopes to skip dead branches in if_statement nodes.
   */
  tryEvalCondition?: (condNode: SyntaxNode, ctx: MapperContextLike) => boolean | null;
}

// ─── Minimal context interface ─────────────────────────────────────────
// The profile functions need access to the mapper context, but we don't want
// a circular import. This interface captures what the profile needs.

export interface MapperContextLike {
  readonly neuralMap: { nodes: any[]; edges: any[]; source_file: string };
  readonly scopeStack: any[];
  readonly functionRegistry: Map<string, string>;
  readonly pendingCalls: Array<{ callerContainerId: string; calleeName: string; isAsync: boolean }>;
  readonly pendingCallbackTaint: Map<string, string>;
  /** Maps function STRUCTURAL node ID -> whether the function returns tainted data.
   *  Set by postVisitFunction, read by PASS 2 return taint propagation. */
  readonly functionReturnTaint: Map<string, boolean>;
  lastCreatedNodeId: string | null;
  nodeSequence: number;
  currentScope: any | null;
  pushScope: (type: ScopeType, node: SyntaxNode, containerNodeId?: string | null) => any;
  popScope: () => any;
  declareVariable: (name: string, kind: VariableInfo['kind'], declaringNodeId?: string | null, tainted?: boolean, producingNodeId?: string | null) => void;
  resolveVariable: (name: string) => VariableInfo | null;
  addDataFlow: (fromNodeId: string, toNodeId: string, name: string, dataType?: string, tainted?: boolean) => void;
  getCurrentContainerId: () => string | null;
  addContainsEdge: (containerNodeId: string, childNodeId: string) => void;
  emitContainsIfNeeded: (childNodeId: string) => void;
  /** V2: Accumulated semantic sentences */
  sentences: SemanticSentence[];
  /** V2: Add a sentence to the accumulator */
  addSentence(s: SemanticSentence): void;
}

// ─── Taint source result ───────────────────────────────────────────────

export interface TaintSourceResult {
  nodeId: string;
  name: string;
}
