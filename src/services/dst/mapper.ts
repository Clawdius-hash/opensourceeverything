// Mapper: transforms a tree-sitter CST into a NeuralMap.
// This skeleton handles scope tracking (push/pop at function/class boundaries)
// and variable resolution. Node classification is driven by a LanguageProfile.

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type Parser from 'web-tree-sitter';
import type { NeuralMap, NeuralMapNode, Edge, Sensitivity, RangeInfo, SemanticSentence, TaintEvent } from './types.js';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { LanguageProfile } from './languageProfile.js';
import { javascriptProfile } from './profiles/javascript.js';
import { resolveSentences } from './sentence-resolver.js';
// NOTE: walkTree from cstWalker.js is NOT imported here.
// walkWithScopes (below) does its own recursive walk because walkTree
// lacks post-visit hooks needed for scope pop.

// ---------------------------------------------------------------------------
// Call node types across all supported languages (tree-sitter grammar names).
// Used by walkWithScopes to track unmapped call expressions in diagnostics.
// ---------------------------------------------------------------------------

const CALL_NODE_TYPES = new Set([
  'call_expression',          // JS, Go, Kotlin, Swift, Rust
  'call',                     // Python, Ruby
  'method_invocation',        // Java
  'invocation_expression',    // C#
  'function_call_expression', // PHP
  'member_call_expression',   // PHP
  'scoped_call_expression',   // PHP
]);

// ---------------------------------------------------------------------------
// Scope infrastructure
// ---------------------------------------------------------------------------

export interface VariableInfo {
  /** Variable name */
  name: string;
  /** ID of the NeuralMapNode that declared this variable (null if not yet classified) */
  declaringNodeId: string | null;
  /** ID of the NeuralMapNode that produced this variable's value (e.g., fetch() → EXTERNAL node) */
  producingNodeId: string | null;
  /** Declaration kind */
  kind: 'let' | 'const' | 'var' | 'param' | 'import';
  /** Whether this variable carries tainted (user-controlled) data */
  tainted: boolean;
  /** If this variable is an alias for a callee (e.g., const q = db.query → ['db', 'query']),
   *  store the chain so resolveCallee can look it up when q() is called. */
  aliasChain?: string[];
  /** If this variable holds a known constant string (e.g., const action = "quer" + "y" → "query"),
   *  store the value for computed property resolution: db[action] → db.query */
  constantValue?: string;
  /** Generic type arguments from the declaration, e.g., Map<String, Statement> → ['String', 'Statement'].
   *  Used to resolve method return types on generic containers (e.g., map.get() returns Statement). */
  genericTypeArgs?: string[];
  /** If this variable holds a known numeric constant (e.g., int num = 106),
   *  store the value for constant propagation and dead branch elimination. */
  numericValue?: number;
  /** Per-index taint tracking for collection variables (List, ArrayList, etc.).
   *  When present, tracks the taint state of each element by index.
   *  When undefined, falls back to whole-collection taint (receiverVar.tainted).
   *  Populated by .add(), updated by .remove(), resolved by .get(). */
  collectionTaint?: Array<{ tainted: boolean; producingNodeId: string | null }>;
  /** Per-key taint tracking for Map/HashMap variables.
   *  When present, tracks the taint state of each value by string key.
   *  Populated by .put(key, value), resolved by .get(key). */
  keyedTaint?: Map<string, { tainted: boolean; producingNodeId: string | null }>;
  /** If this variable has been range-checked by a CONTROL node,
   *  stores the inferred numeric bounds. Used by integer/arithmetic
   *  verifiers to suppress findings on bounded variables. */
  range?: RangeInfo;
}

export type ScopeType = 'module' | 'function' | 'block' | 'class';

export interface Scope {
  /** Unique identifier for this scope */
  id: string;
  /** Parent scope ID, null for module scope */
  parentId: string | null;
  /** What kind of scope this is */
  type: ScopeType;
  /** Variables declared in this scope */
  variables: Map<string, VariableInfo>;
  /** The syntax node that created this scope */
  node: SyntaxNode;
  /** ID of the STRUCTURAL NeuralMapNode that owns this scope (null for module/block scopes without a container) */
  containerNodeId: string | null;
}

// ---------------------------------------------------------------------------
// MapperContext -- stateful context during a single map operation
// ---------------------------------------------------------------------------

export class MapperContext {
  /** Stack of active scopes, bottom = module, top = current */
  readonly scopeStack: Scope[] = [];

  /** The NeuralMap being built */
  readonly neuralMap: NeuralMap;

  /** Counter for generating unique scope IDs */
  private scopeCounter = 0;

  /** Counter for generating unique node IDs (for NeuralMapNodes, used later) */
  nodeSequence = 0;

  /** Tracks the most recently created NeuralMapNode ID.
   *  Set by classification cases (Steps 07-09) whenever a node is pushed.
   *  Read by processVariableDeclaration to link variables to their producing nodes. */
  lastCreatedNodeId: string | null = null;

  /** Registry of function names -> STRUCTURAL node IDs (populated during walk) */
  readonly functionRegistry = new Map<string, string>();

  /** Pending calls to resolve after the walk completes */
  readonly pendingCalls: Array<{
    callerContainerId: string;
    calleeName: string;
    isAsync: boolean;
  }> = [];

  /** Params that should be tainted when their scope is pushed.
   *  Maps param name → producing node ID.
   *  Set by call_expression handler when a callback is passed to a tainted call.
   *  Consumed by processFunctionParams to mark the params as tainted. */
  readonly pendingCallbackTaint = new Map<string, string>();

  /** Maps function STRUCTURAL node ID -> whether the function returns tainted data.
   *  Set by postVisitFunction during the walk, read by PASS 2 Step 4b
   *  to propagate return taint to local_call nodes for forward-referenced functions. */
  readonly functionReturnTaint = new Map<string, boolean>();

  /** Fast lookup: node ID -> NeuralMapNode. Populated via registerNode().
   *  Eliminates O(n) .find() calls in addDataFlow, addContainsEdge,
   *  buildWritesEdges, buildCallsEdges, and propagateInterproceduralTaint. */
  readonly nodeById = new Map<string, NeuralMapNode>();

  /** O(1) edge dedup: tracks "source:target:edgeType" strings to avoid
   *  scanning node.edges[] on every addEdge call. */
  readonly edgeSet = new Set<string>();

  /** Diagnostic counters -- tracks silent failures for post-mapping visibility.
   *  Accessible on the returned context after buildNeuralMap completes. */
  diagnostics = {
    unmappedCalls: 0,
    droppedFlows: 0,
    droppedEdges: 0,
    totalCalls: 0,
    /** Incremented by verifiers when a source-line fallback fires because
     *  the mapper couldn't trace taint through the graph. Each increment
     *  represents a CWE check that had to bypass the graph and regex-scan
     *  source code instead. Higher = more mapper gaps. */
    sourceLineFallbacks: 0,
    /** Per-phase timing in milliseconds. Populated by buildNeuralMap. */
    timing: {
      walkMs: 0,
      postProcessMs: 0,
      totalMs: 0,
    },
  };

  /** The language profile driving this mapping session */
  readonly profile: LanguageProfile;

  /** V2: Accumulated semantic sentences during the walk */
  readonly sentences: SemanticSentence[] = [];

  /** V2: Variable taint history log */
  readonly taintLog: TaintEvent[] = [];

  /** V2: Add a sentence to the accumulator */
  addSentence(s: SemanticSentence): void {
    this.sentences.push(s);
  }

  constructor(sourceFile: string, sourceCode: string, profile: LanguageProfile = javascriptProfile) {
    resetSequence();
    this.neuralMap = createNeuralMap(sourceFile, sourceCode);
    this.profile = profile;
  }

  /**
   * Rebuild the nodeById index from the current neuralMap.nodes array.
   * Call once after the walk completes and before post-processing.
   */
  buildNodeIndex(): void {
    this.nodeById.clear();
    this.edgeSet.clear();
    for (const node of this.neuralMap.nodes) {
      this.nodeById.set(node.id, node);
      // Pre-populate edgeSet from edges created during the walk
      for (const edge of node.edges) {
        this.edgeSet.add(`${node.id}:${edge.target}:${edge.edge_type}`);
      }
    }
  }

  /** The current (innermost) scope, or null if stack is empty */
  get currentScope(): Scope | null {
    return this.scopeStack.length > 0
      ? this.scopeStack[this.scopeStack.length - 1]
      : null;
  }

  /**
   * Push a new scope onto the stack.
   * Returns the new scope for further manipulation.
   */
  pushScope(type: ScopeType, node: SyntaxNode, containerNodeId: string | null = null): Scope {
    this.scopeCounter += 1;
    const parentId = this.currentScope?.id ?? null;
    const scope: Scope = {
      id: `scope_${this.scopeCounter}`,
      parentId,
      type,
      variables: new Map(),
      node,
      containerNodeId,
    };
    this.scopeStack.push(scope);
    return scope;
  }

  /**
   * Pop the current scope off the stack.
   * Returns the popped scope.
   */
  popScope(): Scope | undefined {
    return this.scopeStack.pop();
  }

  /**
   * Declare a variable in the current scope.
   * For 'var' declarations, walks up to the nearest function or module scope.
   */
  declareVariable(
    name: string,
    kind: VariableInfo['kind'],
    declaringNodeId: string | null = null,
    tainted: boolean = false,
    producingNodeId: string | null = null,
  ): void {
    const targetScope = kind === 'var'
      ? this.findVarScope()
      : this.currentScope;

    if (!targetScope) return;

    targetScope.variables.set(name, {
      name,
      declaringNodeId,
      producingNodeId,
      kind,
      tainted,
    });
  }

  /**
   * Resolve a variable by name, walking up the scope chain.
   * Returns the VariableInfo if found, null otherwise.
   */
  resolveVariable(name: string): VariableInfo | null {
    // Walk from innermost scope outward
    for (let i = this.scopeStack.length - 1; i >= 0; i--) {
      const variable = this.scopeStack[i].variables.get(name);
      if (variable) return variable;
    }
    return null;
  }

  /**
   * Create a DataFlow link between two nodes.
   * Adds a data_out entry on the source node and a data_in entry on the target node.
   */
  addDataFlow(
    fromNodeId: string,
    toNodeId: string,
    name: string,
    dataType: string = 'unknown',
    tainted: boolean = false,
    range?: RangeInfo,     // Step 5: optional range propagation
  ): void {
    const fromNode = this.nodeById.get(fromNodeId) ?? this.neuralMap.nodes.find(n => n.id === fromNodeId);
    const toNode = this.nodeById.get(toNodeId) ?? this.neuralMap.nodes.find(n => n.id === toNodeId);
    if (!fromNode || !toNode) {
      this.diagnostics.droppedFlows++;
      return;
    }
    // Cache lookups for future calls
    if (!this.nodeById.has(fromNodeId)) this.nodeById.set(fromNodeId, fromNode);
    if (!this.nodeById.has(toNodeId)) this.nodeById.set(toNodeId, toNode);

    const flow: {
      name: string; source: string; target: string;
      data_type: string; tainted: boolean; sensitivity: 'NONE';
      range?: RangeInfo;
    } = {
      name,
      source: fromNodeId,
      target: toNodeId,
      data_type: dataType,
      tainted,
      sensitivity: 'NONE' as const,
      ...(range !== undefined ? { range } : {}),
    };

    // Avoid duplicate flows (same name, same source/target pair)
    // If a tainted flow arrives and a non-tainted duplicate exists, upgrade to tainted.
    // Taint is NEVER downgraded by dedup.
    const existingOut = fromNode.data_out.find(
      d => d.name === name && d.source === fromNodeId && d.target === toNodeId
    );
    if (existingOut) {
      if (tainted && !existingOut.tainted) existingOut.tainted = true;
      if (range !== undefined && !existingOut.range) existingOut.range = range;
    } else {
      fromNode.data_out.push({ ...flow });
    }

    const existingIn = toNode.data_in.find(
      d => d.name === name && d.source === fromNodeId && d.target === toNodeId
    );
    if (existingIn) {
      if (tainted && !existingIn.tainted) existingIn.tainted = true;
      if (range !== undefined && !existingIn.range) existingIn.range = range;
    } else {
      toNode.data_in.push({ ...flow });
    }
  }

  /**
   * Get the nearest container node ID from the scope stack.
   * Walks from innermost scope outward looking for a scope that has a containerNodeId.
   */
  getCurrentContainerId(): string | null {
    for (let i = this.scopeStack.length - 1; i >= 0; i--) {
      if (this.scopeStack[i]!.containerNodeId) return this.scopeStack[i]!.containerNodeId;
    }
    return null;
  }

  /**
   * Centralized edge creation.  Handles dedup, dual-write to both
   * sourceNode.edges[] and map.edges[], and returns whether a new
   * edge was actually added.
   *
   * @param sourceNodeId  ID of the node the edge originates from
   * @param targetNodeId  ID of the node the edge points to
   * @param edgeType      Relationship type (CONTAINS, DATA_FLOW, …)
   * @param opts          Optional overrides for conditional / async
   * @param sourceNode    If the caller already has the source node object,
   *                      pass it to skip the lookup.
   */
  addEdge(
    sourceNodeId: string,
    targetNodeId: string,
    edgeType: Edge['edge_type'],
    opts?: { conditional?: boolean; async?: boolean },
    sourceNode?: NeuralMapNode,
  ): boolean {
    const src = sourceNode ?? this.nodeById.get(sourceNodeId)
              ?? this.neuralMap.nodes.find(n => n.id === sourceNodeId);
    if (!src) {
      this.diagnostics.droppedEdges++;
      return false;
    }

    // Dedup: O(1) Set lookup instead of O(edges) .some() scan
    const edgeKey = `${sourceNodeId}:${targetNodeId}:${edgeType}`;
    if (this.edgeSet.has(edgeKey)) return false;
    this.edgeSet.add(edgeKey);

    const edge: Edge = {
      target: targetNodeId,
      edge_type: edgeType,
      conditional: opts?.conditional ?? false,
      async: opts?.async ?? false,
    };

    src.edges.push(edge);
    this.neuralMap.edges.push({ ...edge, source: sourceNodeId });
    return true;
  }

  /**
   * Add a CONTAINS edge from container to child.
   * Convenience wrapper around addEdge.
   */
  addContainsEdge(containerNodeId: string, childNodeId: string): void {
    this.addEdge(containerNodeId, childNodeId, 'CONTAINS');
  }

  /**
   * Called after any new node is pushed to neuralMap.nodes.
   * If there is a current container in scope, emits a CONTAINS edge.
   */
  emitContainsIfNeeded(childNodeId: string): void {
    const containerId = this.getCurrentContainerId();
    if (containerId && containerId !== childNodeId) {
      this.addContainsEdge(containerId, childNodeId);
    }
  }

  /**
   * Post-walk: build DATA_FLOW edges from data_in references.
   * For every data_in entry on a node that has a source pointing to another node,
   * creates a DATA_FLOW edge from the source node to the consuming node.
   */
  buildDataFlowEdges(): void {
    for (const node of this.neuralMap.nodes) {
      for (const flow of node.data_in) {
        if (!flow.source || flow.source === 'EXTERNAL') continue;
        const sourceNode = this.nodeById.get(flow.source);
        if (!sourceNode) continue;
        this.addEdge(flow.source, node.id, 'DATA_FLOW', undefined, sourceNode);
      }
    }
  }

  /**
   * Post-walk: build READS edges from STORAGE read nodes to their consumers.
   */
  buildReadsEdges(): void {
    const readSubtypes = new Set(['db_read', 'cache_read', 'state_read']);

    // Pre-build reverse index: sourceId -> consumer nodes that have data_in from that source
    const consumersBySource = new Map<string, NeuralMapNode[]>();
    for (const consumer of this.neuralMap.nodes) {
      for (const flow of consumer.data_in) {
        if (!flow.source || flow.source === 'EXTERNAL') continue;
        let arr = consumersBySource.get(flow.source);
        if (!arr) {
          arr = [];
          consumersBySource.set(flow.source, arr);
        }
        arr.push(consumer);
      }
    }

    for (const node of this.neuralMap.nodes) {
      if (node.node_type !== 'STORAGE') continue;
      if (!readSubtypes.has(node.node_subtype)) continue;

      const consumers = consumersBySource.get(node.id);
      if (!consumers) continue;
      for (const consumer of consumers) {
        if (consumer.id === node.id) continue;
        this.addEdge(node.id, consumer.id, 'READS', undefined, node);
      }
    }
  }

  /**
   * Post-walk: build WRITES edges from data producers to STORAGE write nodes.
   */
  buildWritesEdges(): void {
    const writeSubtypes = new Set(['db_write', 'cache_write', 'state_write']);

    for (const node of this.neuralMap.nodes) {
      if (node.node_type !== 'STORAGE') continue;
      if (!writeSubtypes.has(node.node_subtype)) continue;

      for (const flow of node.data_in) {
        if (!flow.source || flow.source === 'EXTERNAL') continue;
        this.addEdge(flow.source, node.id, 'WRITES');
      }
    }
  }

  /**
   * Post-walk: build DEPENDS edges from module root to imported dependencies.
   * Creates a synthetic module node if no export_statement exists.
   */
  buildDependsEdges(): void {
    const dependencyNodes = this.neuralMap.nodes.filter(
      n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'dependency'
    );

    if (dependencyNodes.length === 0) return;

    let moduleNode = this.neuralMap.nodes.find(
      n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'module'
    );

    if (!moduleNode) {
      moduleNode = createNode({
        label: this.neuralMap.source_file,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: this.profile.id,
        file: this.neuralMap.source_file,
        line_start: 1,
        line_end: 1,
        code_snapshot: `// module: ${this.neuralMap.source_file}`,
        analysis_snapshot: `// module: ${this.neuralMap.source_file}`,
      });
      this.neuralMap.nodes.push(moduleNode);
      this.nodeById.set(moduleNode.id, moduleNode);
    }

    for (const dep of dependencyNodes) {
      this.addEdge(moduleNode.id, dep.id, 'DEPENDS', undefined, moduleNode);
    }
  }

  /**
   * Post-walk PASS 2: Inter-procedural taint propagation.
   *
   * For each function in the registry, compute which of its parameters
   * reach dangerous sinks (STORAGE, EXTERNAL with string concat).
   * Then at every call site where tainted data is passed to such a param,
   * create a DATA_FLOW edge from the tainted INGRESS node → the callee's sink.
   *
   * This is the "function taint summary" approach — a pragmatic alternative
   * to full inter-procedural analysis that handles the most common case:
   *   function helper(input) { db.query("... " + input); }
   *   app.get('/x', (req, res) => { helper(req.query.x); });
   */
  propagateInterproceduralTaint(): void {
    const containedMap = this.buildFunctionContainedNodes();
    const summaries = this.buildFunctionTaintSummaries(containedMap);
    this.connectCallSitesToSinks(summaries);
    const allLocalCalls = this.neuralMap.nodes.filter(n => n.node_subtype === 'local_call');
    this.markLocalCallsTainted(allLocalCalls, summaries);
    this.markLocalCallsReturnTainted(allLocalCalls, containedMap);
    this.connectTaintedLocalCallsToSinks(summaries);
    this.propagateEventEmitterTaint();
  }

  /**
   * Correct functionReturnTaint for passthrough functions where the call-site
   * argument is actually clean. Auto-taint marks all String params as tainted
   * during the walk, but if the caller passes clean data, the function should
   * be considered clean.
   */
  private correctPassthroughReturnTaint(allLocalCalls: NeuralMapNode[]): void {
    const nodeById = this.nodeById;
    const REQUEST_TYPES = /\b(HttpServletRequest|ServletRequest|WebRequest|HttpRequest|HttpServletResponse|ServletResponse)\b/;

    for (const [funcName, funcNodeId] of this.functionRegistry) {
      if (funcName.includes(':')) continue;
      if (this.functionReturnTaint.get(funcNodeId) !== true) continue;

      const funcNode = nodeById.get(funcNodeId);
      if (!funcNode?.param_names || funcNode.param_names.length === 0) continue;

      const snap = funcNode.analysis_snapshot || funcNode.code_snapshot || '';
      const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // Find non-request params
      const sigMatch = snap.match(new RegExp(escaped + '\\s*\\(([^)]*)\\)'));
      const sigText = sigMatch?.[1] ?? '';
      const nonRequestParams: string[] = [];
      for (const pn of funcNode.param_names) {
        const paramTypeRe = new RegExp('(\\w+(?:\\.\\w+)*)\\s+' + pn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
        const ptMatch = sigText.match(paramTypeRe);
        if (!ptMatch || !REQUEST_TYPES.test(ptMatch[1]!)) {
          nonRequestParams.push(pn);
        }
      }
      if (nonRequestParams.length === 0) continue;

      // Check if return depends on a non-request param (passthrough pattern)
      const bodyMatch = snap.match(/\{([\s\S]*)\}/);
      const body = bodyMatch ? bodyMatch[1]! : snap;
      const lines = body.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('//') && !l.startsWith('*'));
      const aliases = new Set(nonRequestParams);
      for (const ln of lines) {
        const assignMatch = ln.match(/^(?:(?:final\s+)?[\w.<>\[\]]+\s+)?(\w+)\s*=\s*(.*)/);
        if (assignMatch) {
          const lhs = assignMatch[1]!;
          let rhs = assignMatch[2]!;
          for (const a of aliases) {
            if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
              aliases.add(lhs);
              break;
            }
          }
        }
        // Track switch case assignments: case 'X': bar = param;
        if (ln.startsWith('case ') || ln.startsWith('default:')) {
          const caseAssign = ln.match(/\b(\w+)\s*=\s*(\w+)\s*;/);
          if (caseAssign) {
            for (const a of aliases) {
              if (caseAssign[2] === a) { aliases.add(caseAssign[1]!); break; }
            }
          }
        }
        // Track if/else inline assignments
        if (ln.startsWith('if ') || ln.startsWith('if(') || ln.startsWith('else ')) {
          const ifAssign = ln.match(/\b(\w+)\s*=\s*([^;]+);/);
          if (ifAssign) {
            for (const a of aliases) {
              if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(ifAssign[2]!)) {
                aliases.add(ifAssign[1]!); break;
              }
            }
          }
        }
      }

      const returnMatch = body.match(/return\s+(\w+)\s*;/);
      if (!returnMatch || !aliases.has(returnMatch[1]!)) continue;

      // Function IS a passthrough. Check ALL call sites: are the non-request args clean?
      for (const lc of allLocalCalls) {
        const lcSnap = lc.analysis_snapshot || lc.code_snapshot || '';
        if (!lcSnap.match(new RegExp('\\b' + escaped + '\\s*\\('))) continue;

        const callArgMatch = lcSnap.match(new RegExp(escaped + '\\s*\\(([^)]*)\\)'));
        if (!callArgMatch) continue;
        const callArgs = callArgMatch[1]!.split(',').map(a => a.trim());

        let allPassthroughArgsClean = true;
        for (let pi = 0; pi < funcNode.param_names.length; pi++) {
          const pn = funcNode.param_names[pi]!;
          if (!nonRequestParams.includes(pn)) continue;
          if (!aliases.has(pn)) continue;
          const argName = callArgs[pi];
          if (!argName) continue;
          // Check if this argument is tainted at the call site
          const argIsTainted = lc.data_in.some(d =>
            d.tainted && d.name && new RegExp('\\b' + argName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(d.name)
          );
          if (argIsTainted) {
            allPassthroughArgsClean = false;
            break;
          }
        }

        if (allPassthroughArgsClean) {
          // The caller passes clean data — function return is actually clean
          this.functionReturnTaint.set(funcNodeId, false);
        }
      }
    }
  }

  // ── PASS 2 sub-steps ────────────────────────────────────────────────

  /** Step 1: BFS from each registered function's STRUCTURAL node to find all contained nodes. */
  private buildFunctionContainedNodes(): Map<string, NeuralMapNode[]> {
    const result = new Map<string, NeuralMapNode[]>();
    const nodeById = this.nodeById;

    for (const [, funcNodeId] of this.functionRegistry) {
      if (!nodeById.get(funcNodeId)) continue;
      const contained: NeuralMapNode[] = [];
      const visited = new Set<string>();
      const queue = [funcNodeId];
      while (queue.length > 0) {
        const currentId = queue.shift()!;
        if (visited.has(currentId)) continue;
        visited.add(currentId);
        const current = nodeById.get(currentId);
        if (!current) continue;
        contained.push(current);
        for (const edge of current.edges) {
          if (edge.edge_type === 'CONTAINS' && !visited.has(edge.target)) {
            queue.push(edge.target);
          }
        }
      }
      result.set(funcNodeId, contained);
    }
    return result;
  }

  /** Step 2: For each function, find sinks whose snapshots reference a parameter name. */
  private buildFunctionTaintSummaries(
    containedMap: Map<string, NeuralMapNode[]>,
  ): Map<string, { funcName: string; funcNodeId: string; sinks: NeuralMapNode[]; paramNames: string[] }> {
    const sinkTypes = new Set(['STORAGE', 'EXTERNAL']);
    const summaries = new Map<string, { funcName: string; funcNodeId: string; sinks: NeuralMapNode[]; paramNames: string[] }>();
    const nodeById = this.nodeById;

    for (const [funcName, funcNodeId] of this.functionRegistry) {
      const contained = containedMap.get(funcNodeId) || [];
      const sinks = contained.filter(n => sinkTypes.has(n.node_type));
      if (sinks.length === 0) continue;

      const funcNode = nodeById.get(funcNodeId);
      if (!funcNode) continue;

      // Prefer AST-extracted param_names (populated during walk) over fragile regex
      let paramNames: string[] = [];
      if (funcNode.param_names && funcNode.param_names.length > 0) {
        paramNames = funcNode.param_names;
      } else {
        const jsPattern = /(?:function\s+\w+\s*|(?:async\s+)?)\(([^)]*)\)|(\w+)\s*=>|\w+\s*\(([^)]*)\)\s*\{/;
        const funcAnalysis = funcNode.analysis_snapshot || funcNode.code_snapshot;
        const paramMatch = (this.profile.functionParamPattern
          ? funcAnalysis.match(this.profile.functionParamPattern)
          : null
        ) || funcAnalysis.match(jsPattern);
        if (paramMatch) {
          const paramStr = paramMatch[1] || paramMatch[2] || paramMatch[3] || '';
          paramNames = paramStr.split(',').map(p => {
            let token = p.trim()
              .replace(/\s*=.*$/, '')
              .replace(/\s*:.*$/, '')
              .replace(/\.{3}/, '')
              .replace(/^\*{1,2}/, '');
            if (this.profile.id === 'java' && /\s/.test(token)) {
              const parts = token.trim().split(/\s+/);
              token = parts[parts.length - 1];
            }
            return token;
          }).filter(Boolean);
        }
      }

      const sinksReferencingParams = sinks.filter(sink =>
        paramNames.some(p => (sink.analysis_snapshot || sink.code_snapshot).includes(p))
      );

      if (sinksReferencingParams.length > 0) {
        summaries.set(funcName, { funcName, funcNodeId, sinks: sinksReferencingParams, paramNames });
      }
    }
    return summaries;
  }

  /** Step 3: At call sites with tainted input, connect to function sinks. */
  private connectCallSitesToSinks(
    summaries: Map<string, { funcName: string; sinks: NeuralMapNode[] }>,
  ): void {
    for (const node of this.neuralMap.nodes) {
      for (const [funcName, summary] of summaries) {
        if ((node.analysis_snapshot || node.code_snapshot).match(new RegExp('\\b' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(')) !== null) {
          if (node.data_in.some(d => d.tainted)) {
            for (const sink of summary.sinks) {
              this.addEdge(node.id, sink.id, 'DATA_FLOW', undefined, node);
            }
          }
          if (this.profile.ingressPattern.test(node.analysis_snapshot || node.code_snapshot)) {
            const ingressNodes = this.neuralMap.nodes.filter(n =>
              n.node_type === 'INGRESS' && n.attack_surface.includes('user_input')
            );
            for (const ingress of ingressNodes) {
              for (const sink of summary.sinks) {
                this.addEdge(ingress.id, sink.id, 'DATA_FLOW', undefined, ingress);
              }
            }
          }
        }
      }
    }
  }

  /** Step 4: Mark local_call nodes tainted if their function has a taint summary. */
  private markLocalCallsTainted(
    allLocalCalls: NeuralMapNode[],
    summaries: Map<string, { funcName: string; sinks: NeuralMapNode[] }>,
  ): void {
    for (const lc of allLocalCalls) {
      if (lc.data_out.some(d => d.tainted)) continue;
      for (const [funcName] of summaries) {
        if ((lc.analysis_snapshot || lc.code_snapshot).match(new RegExp('\\b' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(')) !== null) {
          lc.data_out.push({
            name: 'result', source: lc.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
          });
          break;
        }
      }
    }
  }

  /** Step 4b: Mark local_call nodes tainted via postVisitFunction return taint flags. */
  private markLocalCallsReturnTainted(
    allLocalCalls: NeuralMapNode[],
    containedMap: Map<string, NeuralMapNode[]>,
  ): void {
    const nodeById = this.nodeById;

    // PASS 2a: For local calls and passthrough nodes that were conservatively tainted
    // during the walk (because tainted args were passed), check if the function is now
    // known to NOT return tainted data. If so, remove the conservative taint.
    // This handles the case where a function receives a tainted argument
    // (e.g., HttpServletRequest) but does not propagate that taint through its return.
    // NOTE: passthrough nodes are created for forward-referenced functions that weren't
    // yet in functionRegistry during the walk. They need the same treatment as local_calls.
    const untaintedCallIds = new Set<string>();
    const taintedCallsAndPassthroughs = this.neuralMap.nodes.filter(n =>
      (n.node_subtype === 'local_call' || n.node_subtype === 'passthrough') &&
      n.data_out.some(d => d.tainted)
    );
    for (const lc of taintedCallsAndPassthroughs) {
      for (const [funcName, funcNodeId] of this.functionRegistry) {
        // Skip overloaded variants (name:count) to avoid double-processing
        if (funcName.includes(':')) continue;
        const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if ((lc.analysis_snapshot || lc.code_snapshot).match(
          new RegExp('\\b' + escaped + '\\s*\\(')
        ) !== null) {
          // If the function was analyzed AND explicitly returns clean data, remove
          // the conservative taint. Three-valued: true=tainted, false=clean, undefined=unanalyzed.
          if (this.functionReturnTaint.get(funcNodeId) === false) {
            // GUARD: Before removing taint, check if the function is a potential
            // passthrough — a non-request parameter flows through to the return.
            // The mapper doesn't propagate call-site argument taint into function
            // parameter scopes (only HttpServletRequest/Response types are auto-tainted).
            // So functionReturnTaint may be false even when the function passes tainted
            // data through. Check if the function body returns a value derived from a
            // non-request formal parameter. If so, preserve conservative taint.
            const funcNode = nodeById.get(funcNodeId);
            const paramNames = funcNode?.param_names;
            let isPassthrough = false;
            if (funcNode && paramNames && paramNames.length > 0) {
              const snap = funcNode.analysis_snapshot || funcNode.code_snapshot || '';
              // Identify non-request params (those that aren't HttpServletRequest/Response)
              const REQUEST_TYPES = /\b(HttpServletRequest|ServletRequest|WebRequest|HttpRequest|HttpServletResponse|ServletResponse)\b/;
              // Extract param declarations from the function signature
              const sigMatch = snap.match(new RegExp(escaped.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(([^)]*)\\)'));
              const sigText = sigMatch?.[1] ?? '';
              const nonRequestParams: string[] = [];
              for (const pn of paramNames) {
                // Check if this parameter's type in the signature is a request type
                const paramTypeRe = new RegExp('(\\w+(?:\\.\\w+)*)\\s+' + pn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
                const ptMatch = sigText.match(paramTypeRe);
                if (!ptMatch || !REQUEST_TYPES.test(ptMatch[1]!)) {
                  nonRequestParams.push(pn);
                }
              }
              if (nonRequestParams.length > 0) {
                // Check if the return statement references any non-request param
                // (directly or transitively via simple assignment chains).
                // Look for: return <expr containing paramName>
                // Also handle: bar = param; return bar;
                const bodyMatch = snap.match(/\{([\s\S]*)\}/);
                const body = bodyMatch ? bodyMatch[1]! : snap;
                const lines = body.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('//') && !l.startsWith('*'));
                const aliases = new Set(nonRequestParams);
                for (let li = 0; li < lines.length; li++) {
                  const ln = lines[li]!;
                  // Track simple assignments: bar = param; or bar = someFunc(param);
                  const assignMatch = ln.match(/^(?:(?:final\s+)?[\w.<>\[\]]+\s+)?(\w+)\s*=\s*(.*)/);
                  if (assignMatch) {
                    const lhs = assignMatch[1]!;
                    // Handle multi-line expressions: if the RHS doesn't end with ';',
                    // concatenate subsequent lines until we find a semicolon.
                    // This catches patterns like: bar = \n new String(\n B64.decode(\n ... param.getBytes()));
                    let rhs = assignMatch[2]!;
                    if (!rhs.includes(';') && li + 1 < lines.length) {
                      for (let ci = li + 1; ci < lines.length; ci++) {
                        rhs += ' ' + lines[ci]!;
                        if (lines[ci]!.includes(';')) break;
                      }
                    }
                    for (const a of aliases) {
                      if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
                        aliases.add(lhs);
                        break;
                      }
                    }
                  }
                  // Track if/else inline assignments: if (cond) bar = param; or else bar = param;
                  // These don't match the standard assignment regex because the line starts with if/else.
                  // Use a broader pattern that finds any "word = expr" within the line, even after
                  // complex if conditions with nested parentheses.
                  if (!assignMatch && (ln.startsWith('if ') || ln.startsWith('if(') || ln.startsWith('else '))) {
                    // Find the last assignment pattern in the line: look for word = word/expr ;
                    const ifAssignMatch = ln.match(/\b(\w+)\s*=\s*([^;]+);/);
                    if (ifAssignMatch) {
                      const lhs = ifAssignMatch[1]!;
                      const rhs = ifAssignMatch[2]!;
                      for (const a of aliases) {
                        if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
                          aliases.add(lhs);
                          break;
                        }
                      }
                    }
                  }
                  // Track ternary: bar = cond ? "safe" : param;
                  const ternMatch = ln.match(/^(?:[\w.<>\[\]]+\s+)?(\w+)\s*=.*\?.*:(.*)/);
                  if (ternMatch) {
                    const lhs = ternMatch[1]!;
                    const rhs = ternMatch[2]!;
                    for (const a of aliases) {
                      if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
                        aliases.add(lhs);
                        break;
                      }
                    }
                  }
                  // Track map.put("key", param) + bar = map.get("key")
                  const putMatch = ln.match(/(\w+)\.put\s*\(\s*"([^"]*)"\s*,\s*(\w+)\s*\)/);
                  if (putMatch) {
                    for (const a of aliases) {
                      if (putMatch[3] === a) {
                        // Mark the map+key as an alias source
                        aliases.add(`__map_${putMatch[1]}_${putMatch[2]}`);
                        break;
                      }
                    }
                  }
                  const getMatch = ln.match(/(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
                  if (getMatch && aliases.has(`__map_${getMatch[2]}_${getMatch[3]}`)) {
                    aliases.add(getMatch[1]!);
                  }
                }
                // Now check return statements
                const returnMatch = body.match(/return\s+(\w+)\s*;/);
                if (returnMatch && aliases.has(returnMatch[1]!)) {
                  // The function textually passes a non-request param to return.
                  // But we also need to check: is the actual call-site argument
                  // corresponding to that param tainted? If not, this passthrough
                  // is safe (the non-request param carries safe data at this call site).
                  // Extract arg names from the call-site code and match by position.
                  const callSnap = lc.analysis_snapshot || lc.code_snapshot || '';
                  const callArgMatch = callSnap.match(new RegExp(escaped + '\\s*\\(([^)]*)\\)'));
                  if (callArgMatch) {
                    const callArgs = callArgMatch[1]!.split(',').map(a => a.trim());
                    // Find which passthrough params (that alias to the return) have
                    // tainted call-site arguments.
                    let hasAnyTaintedPassthroughArg = false;
                    for (let pi = 0; pi < paramNames.length; pi++) {
                      const pn = paramNames[pi]!;
                      if (!nonRequestParams.includes(pn)) continue;
                      if (!aliases.has(pn)) continue; // this param doesn't flow to return
                      // Get the corresponding call-site argument
                      const argName = callArgs[pi];
                      if (!argName) continue;
                      // Check if this argument is tainted in the call node's data_in
                      const argIsTainted = lc.data_in.some(d =>
                        d.tainted && d.name && new RegExp('\\b' + argName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(d.name)
                      );
                      if (argIsTainted) {
                        hasAnyTaintedPassthroughArg = true;
                        break;
                      }
                    }
                    isPassthrough = hasAnyTaintedPassthroughArg;
                  } else {
                    // Can't parse call-site args — conservatively treat as passthrough
                    isPassthrough = true;
                  }
                }
              }
            }
            if (!isPassthrough) {
              lc.data_out = lc.data_out.filter(d => !d.tainted);
              untaintedCallIds.add(lc.id);
            }
          }
          break;
        }
      }
    }

    // PASS 2a cleanup: propagate un-tainting to downstream nodes.
    // When a local call's taint is removed:
    // 1. Un-taint data_in entries sourced from the local call
    // 2. Remove DATA_FLOW edges from the local call to downstream nodes
    // 3. Remove DATA_FLOW edges from the global edges list
    if (untaintedCallIds.size > 0) {
      for (const node of this.neuralMap.nodes) {
        // Clean data_in entries sourced from un-tainted local calls
        node.data_in = node.data_in.map(d => {
          if (d.tainted && d.source && untaintedCallIds.has(d.source)) {
            return { ...d, tainted: false };
          }
          return d;
        });
        // Clean data_out entries sourced from un-tainted local calls
        node.data_out = node.data_out.map(d => {
          if (d.tainted && d.source && untaintedCallIds.has(d.source)) {
            return { ...d, tainted: false };
          }
          return d;
        });
        // Remove outgoing DATA_FLOW edges from un-tainted local calls
        // (these edges represent incorrect taint propagation paths)
        if (untaintedCallIds.has(node.id)) {
          for (const e of node.edges) {
            if (e.edge_type === 'DATA_FLOW') {
              this.edgeSet.delete(`${node.id}:${e.target}:DATA_FLOW`);
            }
          }
          node.edges = node.edges.filter(e => e.edge_type !== 'DATA_FLOW');
        }
      }
      // Also clean the global edges list
      this.neuralMap.edges = this.neuralMap.edges.filter(e =>
        !(e.edge_type === 'DATA_FLOW' && e.source && untaintedCallIds.has(e.source))
      );
    }

    // PASS 2b: For local calls that are NOT yet tainted, add taint if the function
    // is now known to return tainted data (forward-referenced functions).
    for (const lc of allLocalCalls) {
      if (lc.data_out.some(d => d.tainted)) continue;
      for (const [funcName, funcNodeId] of this.functionRegistry) {
        const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if ((lc.analysis_snapshot || lc.code_snapshot).match(
          new RegExp('\\b' + escaped + '\\s*\\(')
        ) !== null) {
          // Only mark the call as tainted if postVisitFunction explicitly set the
          // functionReturnTaint flag (meaning a return statement referenced tainted data).
          // Previously we also checked funcNode.data_out.some(d => d.tainted), which
          // fired whenever the STRUCTURAL node had ANY tainted data_out — including from
          // parameter processing or containment, not just return taint. This caused excess
          // taint propagation and noise (e.g., 17 extra FPs on CWE-526 servlet files).
          if (this.functionReturnTaint.get(funcNodeId) !== true) break;

          // Extra guard: verify the function's code has a return statement referencing
          // a tainted variable name. This prevents tainting when the return doesn't
          // actually propagate tainted data (e.g., returns a constant or unrelated var).
          const funcNode = nodeById.get(funcNodeId);
          const contained = containedMap.get(funcNodeId) || [];
          const taintedNames = contained
            .filter(n => n.data_out.some(d => d.tainted) && n.node_type !== 'STRUCTURAL')
            .map(n => n.label.replace(/\s*=\s*$/, '').trim())
            .filter(name => name.length > 0 && name.length < 40);
          const snap = funcNode?.analysis_snapshot || funcNode?.code_snapshot || '';
          const hasReturnWithTaint = taintedNames.length === 0 ||
            taintedNames.some(name => {
              const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
              return new RegExp(`return\\s+[^;]*\\b${esc}\\b`).test(snap);
            });
          if (!hasReturnWithTaint) break;

          lc.data_out.push({
            name: 'return', source: lc.id, data_type: 'unknown',
            tainted: true, sensitivity: 'NONE' as const,
          });
          const ingressInFunc = contained.find(n => n.node_type === 'INGRESS');
          if (ingressInFunc) {
            this.addEdge(ingressInFunc.id, lc.id, 'DATA_FLOW', undefined, ingressInFunc);
          }
          break;
        }
      }
    }
  }

  /** Step 5: Connect tainted local_call return values to consumer sinks. */
  private connectTaintedLocalCallsToSinks(
    summaries: Map<string, { funcName: string; sinks: NeuralMapNode[] }>,
  ): void {
    const taintedLocalCalls = this.neuralMap.nodes.filter(n =>
      n.node_subtype === 'local_call' && n.data_out.some(d => d.tainted)
    );
    const sinkNodes = this.neuralMap.nodes.filter(n =>
      n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL'
    );
    for (const lc of taintedLocalCalls) {
      for (const sink of sinkNodes) {
        if ((sink.analysis_snapshot || sink.code_snapshot).includes(lc.label.slice(0, 30)) && sink.id !== lc.id) {
          this.addEdge(lc.id, sink.id, 'DATA_FLOW', undefined, lc);
        }
      }
      for (const summary of summaries.values()) {
        if ((lc.analysis_snapshot || lc.code_snapshot).includes(summary.funcName + '(')) {
          for (const sink of summary.sinks) {
            this.addEdge(lc.id, sink.id, 'DATA_FLOW', undefined, lc);
          }
        }
      }
    }
  }

  /** Step 6: Propagate taint through event emitter .emit() / .on() pairs. */
  private propagateEventEmitterTaint(): void {
    const emitPattern = /\.emit\s*\(\s*['"](\w+)['"]/;
    const onPattern = /\.on\s*\(\s*['"](\w+)['"]/;

    const emitNodes: Array<{ node: NeuralMapNode; eventName: string }> = [];
    const onNodes: Array<{ node: NeuralMapNode; eventName: string }> = [];

    for (const node of this.neuralMap.nodes) {
      const emitMatch = (node.analysis_snapshot || node.code_snapshot).match(emitPattern);
      if (emitMatch) emitNodes.push({ node, eventName: emitMatch[1] });
      const onMatch = (node.analysis_snapshot || node.code_snapshot).match(onPattern);
      if (onMatch) onNodes.push({ node, eventName: onMatch[1] });
    }

    for (const emit of emitNodes) {
      const hasTaint = emit.node.data_in.some(d => d.tainted) ||
        this.profile.ingressPattern.test(emit.node.analysis_snapshot || emit.node.code_snapshot);
      if (!hasTaint) continue;

      const matchingHandlers = onNodes.filter(on => on.eventName === emit.eventName);
      for (const handler of matchingHandlers) {
        const handlerLine = handler.node.line_start;
        const nearbySinks = this.neuralMap.nodes.filter(n =>
          (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
          n.line_start >= handlerLine && n.line_start <= handlerLine + 20
        );
        const ingressNodes = this.neuralMap.nodes.filter(n =>
          n.node_type === 'INGRESS' && n.attack_surface.includes('user_input')
        );
        for (const sink of nearbySinks) {
          for (const ingress of ingressNodes) {
            this.addEdge(ingress.id, sink.id, 'DATA_FLOW', undefined, ingress);
          }
        }
      }
    }
  }

  /**
   * Post-walk: resolve pending calls against the function registry
   * and emit CALLS edges.
   */
  buildCallsEdges(): void {
    for (const pending of this.pendingCalls) {
      const calleeNodeId = this.functionRegistry.get(pending.calleeName);
      if (!calleeNodeId) continue;
      if (calleeNodeId === pending.callerContainerId) continue;
      this.addEdge(pending.callerContainerId, calleeNodeId, 'CALLS',
        { async: pending.isAsync });
    }
  }

  /**
   * Find the nearest function or module scope for 'var' hoisting.
   */
  private findVarScope(): Scope | null {
    for (let i = this.scopeStack.length - 1; i >= 0; i--) {
      const scope = this.scopeStack[i];
      if (scope.type === 'function' || scope.type === 'module') {
        return scope;
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Detect data sensitivity from a variable or parameter name.
 * Returns the highest sensitivity classification that matches.
 *
 * Priority: SECRET > PII > AUTH > FINANCIAL > NONE
 */
function detectSensitivity(name: string): Sensitivity {
  const lower = name.toLowerCase();

  // SECRET: passwords, tokens, API keys, secrets
  const secretPatterns = [
    'password', 'passwd', 'pwd', 'secret', 'token',
    'api_key', 'apikey', 'api-key', 'private_key', 'privatekey',
    'access_key', 'accesskey', 'secret_key', 'secretkey',
  ];
  if (secretPatterns.some(p => lower.includes(p))) {
    return 'SECRET';
  }

  // PII: personally identifiable information
  const piiPatterns = [
    'email', 'phone', 'address', 'ssn', 'social_security',
    'dob', 'date_of_birth', 'birthdate', 'firstname', 'first_name',
    'lastname', 'last_name', 'fullname', 'full_name',
    'zipcode', 'zip_code', 'postal',
  ];
  if (piiPatterns.some(p => lower.includes(p))) {
    return 'PII';
  }

  // AUTH: authentication/authorization data
  const authPatterns = [
    'session', 'auth', 'jwt', 'cookie', 'bearer',
    'credential', 'oauth', 'refresh_token', 'id_token',
  ];
  if (authPatterns.some(p => lower.includes(p))) {
    return 'AUTH';
  }

  // FINANCIAL: money/payment data
  const financialPatterns = [
    'amount', 'price', 'balance', 'credit', 'payment',
    'card_number', 'cardnumber', 'cvv', 'expiry',
    'account_number', 'routing', 'iban', 'swift',
  ];
  if (financialPatterns.some(p => lower.includes(p))) {
    return 'FINANCIAL';
  }

  return 'NONE';
}

/**
 * Post-processing pass: initialize taint markers on all DataFlow entries.
 *
 * Rules:
 * - INGRESS nodes: all data_out is tainted (user-controlled input)
 * - EXTERNAL nodes: all data_out is tainted (external data, untrusted)
 * - TRANSFORM/sanitize: data_out is NOT tainted (sanitizer clears taint)
 * - TRANSFORM/encrypt: data_out is NOT tainted (encryption transforms data)
 * - All other nodes: data_out taint is unchanged (preserves whatever was set during construction)
 *
 * Also applies sensitivity detection to all DataFlow entries based on their name.
 */
function initializeTaint(map: NeuralMap): void {
  for (const node of map.nodes) {
    // INGRESS: all output data is tainted
    if (node.node_type === 'INGRESS') {
      for (const flow of node.data_out) {
        flow.tainted = true;
      }
    }

    // EXTERNAL: return data is tainted (came from outside the system)
    if (node.node_type === 'EXTERNAL') {
      for (const flow of node.data_out) {
        flow.tainted = true;
      }
    }

    // TRANSFORM/sanitize: sanitizer clears taint
    if (node.node_type === 'TRANSFORM' && node.node_subtype === 'sanitize') {
      for (const flow of node.data_out) {
        flow.tainted = false;
      }
    }

    // TRANSFORM/encrypt: encryption clears taint (data is no longer raw user input)
    if (node.node_type === 'TRANSFORM' && node.node_subtype === 'encrypt') {
      for (const flow of node.data_out) {
        flow.tainted = false;
      }
    }

    // Apply sensitivity detection to ALL data flows (both in and out)
    for (const flow of node.data_out) {
      const sensitivity = detectSensitivity(flow.name);
      if (sensitivity !== 'NONE') {
        flow.sensitivity = sensitivity;
      }
    }
    for (const flow of node.data_in) {
      const sensitivity = detectSensitivity(flow.name);
      if (sensitivity !== 'NONE') {
        flow.sensitivity = sensitivity;
      }
    }
  }
}


/**
 * Build a NeuralMap from a parsed tree-sitter tree.
 *
 * This skeleton version:
 * - Creates the root module scope
 * - Walks the tree depth-first
 * - Pushes/pops scopes at function, class, and block boundaries
 * - Declares variables at variable_declaration/lexical_declaration nodes
 * - Declares function parameters when entering function scopes
 * - Returns a NeuralMap with 0 classified nodes (classification comes in Goal 3)
 *
 * The MapperContext is returned alongside the NeuralMap for testing purposes.
 */
export function buildNeuralMap(
  tree: Parser.Tree,
  sourceCode: string,
  fileName: string,
  profile: LanguageProfile = javascriptProfile,
): { map: NeuralMap; ctx: MapperContext } {
  const t0 = performance.now();
  const ctx = new MapperContext(fileName, sourceCode, profile);
  const root = tree.rootNode;

  // Push module-level scope
  ctx.pushScope('module', root);

  // We need to handle scope push/pop manually during walk because
  // walkTree doesn't give us a post-visit hook. Instead, we use
  // the tree cursor for a proper enter/leave traversal.
  walkWithScopes(root, ctx, profile);

  const tWalkDone = performance.now();

  // NOTE: We intentionally do NOT pop the module scope here.
  // The module scope remains on ctx.scopeStack so that callers can use
  // ctx.resolveVariable() on the returned context (e.g., for constant-folding tests).

  // Post-processing: build node index for O(1) lookups in post-walk passes
  ctx.buildNodeIndex();

  // Post-processing: initialize taint markers and detect sensitivity
  initializeTaint(ctx.neuralMap);

  // Post-processing: resolve CALLS edges
  ctx.buildCallsEdges();

  // Post-processing: build DATA_FLOW edges from data_in references
  ctx.buildDataFlowEdges();

  // Post-processing: PASS 2 -- inter-procedural taint propagation
  ctx.propagateInterproceduralTaint();

  // Post-processing: build READS, WRITES, DEPENDS edges
  ctx.buildReadsEdges();
  ctx.buildWritesEdges();
  ctx.buildDependsEdges();

  // V2: Resolve PENDING taint in sentences using inter-procedural analysis results
  resolveSentences(ctx);

  // V2: Assemble story from accumulated sentences, sorted by line number
  if (ctx.sentences.length > 0) {
    ctx.neuralMap.story = [...ctx.sentences].sort((a, b) => a.lineNumber - b.lineNumber);
  }

  const tDone = performance.now();
  ctx.diagnostics.timing.walkMs = Math.round(tWalkDone - t0);
  ctx.diagnostics.timing.postProcessMs = Math.round(tDone - tWalkDone);
  ctx.diagnostics.timing.totalMs = Math.round(tDone - t0);

  return { map: ctx.neuralMap, ctx };
}

/** Extract constant value from a switch case label */
function tryFoldCaseLabel(expr: SyntaxNode): string | null {
  if (expr.type === 'character_literal') return expr.text.replace(/^'|'$/g, '');
  if (expr.type === 'string_literal') return expr.text.replace(/^"|"$/g, '');
  if (expr.type === 'decimal_integer_literal') return expr.text;
  return null;
}

/** Check if a switch group ends with break/return/throw */
function groupEndsWithBreak(group: SyntaxNode): boolean {
  for (let i = group.namedChildCount - 1; i >= 0; i--) {
    const child = group.namedChild(i);
    if (!child || child.type === 'switch_label') continue;
    return child.type === 'break_statement' || child.type === 'return_statement'
        || child.type === 'throw_statement' || child.type === 'continue_statement';
  }
  return false;
}

/**
 * Walk the tree with proper scope push/pop on enter and leave.
 * This is a recursive walk that gives us both pre-order and post-order hooks.
 * The LanguageProfile drives all language-specific decisions.
 */
function walkWithScopes(node: SyntaxNode, ctx: MapperContext, profile: LanguageProfile): void {
  const scopeType = profile.getScopeType(node);
  let pushedScope = false;

  // Enter: push scope if this node creates one
  if (scopeType && node !== ctx.scopeStack[0]?.node) {
    ctx.pushScope(scopeType, node);
    pushedScope = true;

    // If this is a function scope, declare its parameters
    if (scopeType === 'function') {
      profile.processFunctionParams(node, ctx);
    }

    // If this is a class, declare the class name in the OUTER scope
    // (it was already pushed, so we need to declare in parent)
    if (scopeType === 'class') {
      const className = node.childForFieldName('name');
      if (className && ctx.scopeStack.length >= 2) {
        const parentScope = ctx.scopeStack[ctx.scopeStack.length - 2];
        parentScope.variables.set(className.text, {
          name: className.text,
          declaringNodeId: null,
          producingNodeId: null,
          kind: 'const',
          tainted: false,
        });
      }
    }
  }

  // ── Pre-visit iteration hook (for-of/for-in loop variable taint) ──
  if (profile.preVisitIteration) {
    profile.preVisitIteration(node, ctx);
  }

  // ── VALUE-FIRST WALKING for variable declarations ──
  if (profile.isValueFirstDeclaration(node.type)) {
    ctx.lastCreatedNodeId = null;
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) walkWithScopes(child, ctx, profile);
    }
    profile.processVariableDeclaration(node, ctx);
    if (pushedScope) ctx.popScope();
    return; // children already walked
  }

  // ── Node classification — delegated to the language profile ──
  // Track call expression classification for diagnostics
  const isCallNode = CALL_NODE_TYPES.has(node.type);
  const prevNodeId = isCallNode ? ctx.lastCreatedNodeId : null;
  if (isCallNode) ctx.diagnostics.totalCalls++;

  profile.classifyNode(node, ctx);

  // If this was a call node and classifyNode didn't produce a new typed node,
  // it means the callee couldn't be resolved — count it as unmapped.
  if (isCallNode && ctx.lastCreatedNodeId === prevNodeId) {
    ctx.diagnostics.unmappedCalls++;
  }

  // ── Dead-branch elimination for if_statement / if_expression ──
  // When the profile provides tryEvalCondition and the node is an if-statement,
  // evaluate the condition statically. If the result is known (true/false),
  // skip the dead branch to prevent it from clobbering taint set by the live branch.
  // This handles patterns like: if ((500/42)+num > 200) bar = param; else bar = "safe";
  const isIfNode = node.type === 'if_statement' || node.type === 'if_expression';
  let skipConsequence = false;
  let skipAlternative = false;
  if (isIfNode && profile.tryEvalCondition) {
    const condNode = node.childForFieldName('condition');
    if (condNode) {
      const condResult = profile.tryEvalCondition(condNode, ctx);
      if (condResult === true) skipAlternative = true;   // condition always true: skip else
      if (condResult === false) skipConsequence = true;  // condition always false: skip then
      if (condResult === true || condResult === false) {
        const _dbContainerId = ctx.getCurrentContainerId();
        if (_dbContainerId) {
          const _dbContainer = ctx.nodeById.get(_dbContainerId);
          if (_dbContainer && !_dbContainer.metadata.dead_branch_eliminated) {
            _dbContainer.metadata.dead_branch_eliminated = true;
          }
        }
      }
    }
  }

  // Recurse into children
  const isStatementContainer = profile.isStatementContainer(node.type);

  // ── Dead-branch elimination for switch blocks ──
  // NOTE: tree-sitter creates new JS wrapper objects on each node access, so
  // Set<SyntaxNode> identity comparisons do NOT work. Use Set<number> (node.id) instead.
  const isSwitchBlock = node.type === 'switch_block';
  const deadSwitchChildIds = new Set<number>();
  if (isSwitchBlock && profile.tryEvalSwitchTarget && node.parent?.type === 'switch_expression') {
    const condNode = node.parent.childForFieldName('condition');
    if (condNode) {
      const targetValue = profile.tryEvalSwitchTarget(condNode, ctx);
      if (targetValue !== null) {
        // Find which groups are live vs dead
        const allGroups: SyntaxNode[] = [];
        for (let i = 0; i < node.namedChildCount; i++) {
          const g = node.namedChild(i);
          if (g && (g.type === 'switch_block_statement_group' || g.type === 'switch_rule')) {
            allGroups.push(g);
          }
        }

        let matchedIdx = -1;
        let defaultIdx = -1;
        for (let i = 0; i < allGroups.length; i++) {
          const group = allGroups[i];
          let isDefault = false;
          let matches = false;
          for (let j = 0; j < group.namedChildCount; j++) {
            const child = group.namedChild(j);
            if (child?.type !== 'switch_label') continue;
            const labelExpr = child.namedChild(0);
            if (!labelExpr) { isDefault = true; }
            else {
              const labelValue = tryFoldCaseLabel(labelExpr);
              if (labelValue === targetValue) matches = true;
            }
          }
          if (matches && matchedIdx === -1) matchedIdx = i;
          if (isDefault) defaultIdx = i;
        }

        // Determine live group(s)
        const liveIdx = matchedIdx !== -1 ? matchedIdx : defaultIdx;
        if (liveIdx !== -1) {
          const liveGroupIds = new Set<number>();
          liveGroupIds.add(allGroups[liveIdx].id);
          // Handle fall-through
          if (allGroups[liveIdx].type !== 'switch_rule' && !groupEndsWithBreak(allGroups[liveIdx])) {
            for (let k = liveIdx + 1; k < allGroups.length; k++) {
              liveGroupIds.add(allGroups[k].id);
              if (allGroups[k].type === 'switch_rule' || groupEndsWithBreak(allGroups[k])) break;
            }
          }
          // Mark dead groups by their node ID
          for (const g of allGroups) {
            if (!liveGroupIds.has(g.id)) deadSwitchChildIds.add(g.id);
          }
          // Tag container for diagnostics
          const _dbContainerId = ctx.getCurrentContainerId();
          if (_dbContainerId) {
            const _dbContainer = ctx.nodeById.get(_dbContainerId);
            if (_dbContainer && !_dbContainer.metadata.dead_branch_eliminated) {
              _dbContainer.metadata.dead_branch_eliminated = true;
            }
          }
        }
      }
    }
  }

  // ── Inner class pre-walk: for class_body nodes, walk class_declaration children FIRST ──
  // This ensures inner class methods are fully resolved before outer methods can reference them.
  if (node.type === 'class_body') {
    const savedLastNodeId = ctx.lastCreatedNodeId;
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type === 'class_declaration') {
        walkWithScopes(child, ctx, profile);
      }
    }
    ctx.lastCreatedNodeId = savedLastNodeId;

    // Now walk non-class-declaration children (methods, fields, etc.)
    for (let i = 0; i < node.childCount; i++) {
      if (isStatementContainer) ctx.lastCreatedNodeId = null;
      const child = node.child(i);
      if (!child) continue;
      if (child.type === 'class_declaration') continue; // already walked above
      walkWithScopes(child, ctx, profile);
    }

    // Post-visit hooks
    if (profile.postVisitIteration) {
      profile.postVisitIteration(node, ctx);
    }
    if (profile.postVisitFunction) {
      profile.postVisitFunction(node, ctx);
    }

    if (pushedScope) ctx.popScope();
    return; // skip the normal single-pass iteration below
  }

  for (let i = 0; i < node.childCount; i++) {
    if (isStatementContainer) {
      ctx.lastCreatedNodeId = null;
    }
    const child = node.child(i);
    if (child) {
      // Dead-branch skip: if the child is the consequence or alternative of an if-statement
      // and we determined that branch is dead, don't walk it.
      if (isIfNode) {
        const fieldName = node.fieldNameForChild(i);
        if (skipConsequence && fieldName === 'consequence') continue;
        if (skipAlternative && fieldName === 'alternative') continue;
      }
      // Dead-branch skip: if the child is a dead switch group, skip it.
      if (deadSwitchChildIds.size > 0 && deadSwitchChildIds.has(child.id)) continue;
      walkWithScopes(child, ctx, profile);
    }
  }

  // Post-visit hooks — delegated to the language profile
  if (profile.postVisitIteration) {
    profile.postVisitIteration(node, ctx);
  }
  if (profile.postVisitFunction) {
    profile.postVisitFunction(node, ctx);
  }

  // Leave: pop scope if we pushed one
  if (pushedScope) {
    ctx.popScope();
  }
}
