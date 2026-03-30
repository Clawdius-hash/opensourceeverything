// Mapper: transforms a tree-sitter CST into a NeuralMap.
// This skeleton handles scope tracking (push/pop at function/class boundaries)
// and variable resolution. Node classification is driven by a LanguageProfile.

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type Parser from 'web-tree-sitter';
import type { NeuralMap, NeuralMapNode, Edge, Sensitivity } from './types.js';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { LanguageProfile } from './languageProfile.js';
import { javascriptProfile } from './profiles/javascript.js';
// NOTE: walkTree from cstWalker.js is NOT imported here.
// walkWithScopes (below) does its own recursive walk because walkTree
// lacks post-visit hooks needed for scope pop.

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

  /** The language profile driving this mapping session */
  readonly profile: LanguageProfile;

  constructor(sourceFile: string, sourceCode: string, profile: LanguageProfile = javascriptProfile) {
    resetSequence();
    this.neuralMap = createNeuralMap(sourceFile, sourceCode);
    this.profile = profile;
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
  ): void {
    const fromNode = this.neuralMap.nodes.find(n => n.id === fromNodeId);
    const toNode = this.neuralMap.nodes.find(n => n.id === toNodeId);
    if (!fromNode || !toNode) return;

    const flow = {
      name,
      source: fromNodeId,
      target: toNodeId,
      data_type: dataType,
      tainted,
      sensitivity: 'NONE' as const,
    };

    // Avoid duplicate flows (same name, same source/target pair)
    const alreadyOut = fromNode.data_out.some(
      d => d.name === name && d.source === fromNodeId && d.target === toNodeId
    );
    if (!alreadyOut) {
      fromNode.data_out.push({ ...flow });
    }

    const alreadyIn = toNode.data_in.some(
      d => d.name === name && d.source === fromNodeId && d.target === toNodeId
    );
    if (!alreadyIn) {
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
   * Add a CONTAINS edge from container to child.
   * Adds to both the container node's edges array AND the top-level map.edges.
   */
  addContainsEdge(containerNodeId: string, childNodeId: string): void {
    const edge: Edge = {
      target: childNodeId,
      edge_type: 'CONTAINS',
      conditional: false,
      async: false,
    };
    // Add to container node's edges array
    const container = this.neuralMap.nodes.find(n => n.id === containerNodeId);
    if (container) {
      container.edges.push(edge);
    }
    // Add to top-level edges
    this.neuralMap.edges.push({ ...edge });
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
    // Build a fast lookup: node ID -> NeuralMapNode
    const nodeById = new Map<string, NeuralMapNode>();
    for (const node of this.neuralMap.nodes) {
      nodeById.set(node.id, node);
    }

    for (const node of this.neuralMap.nodes) {
      for (const flow of node.data_in) {
        // Skip external sources -- they have no source node in the map
        if (!flow.source || flow.source === 'EXTERNAL') continue;

        const sourceNode = nodeById.get(flow.source);
        if (!sourceNode) continue; // source node doesn't exist (defensive)

        // Check for duplicate: same source -> same target with DATA_FLOW
        const alreadyExists = sourceNode.edges.some(
          e => e.edge_type === 'DATA_FLOW' && e.target === node.id
        );
        if (alreadyExists) continue;

        const edge: Edge = {
          target: node.id,
          edge_type: 'DATA_FLOW',
          conditional: false,
          async: false,
        };

        // Add to source node's edges array (edge points FROM source TO consumer)
        sourceNode.edges.push(edge);

        // Add to top-level edges
        this.neuralMap.edges.push({ ...edge });
      }
    }
  }

  /**
   * Post-walk: build READS edges from STORAGE read nodes to their consumers.
   */
  buildReadsEdges(): void {
    const readSubtypes = new Set(['db_read', 'cache_read', 'state_read']);

    for (const node of this.neuralMap.nodes) {
      if (node.node_type !== 'STORAGE') continue;
      if (!readSubtypes.has(node.node_subtype)) continue;

      for (const consumer of this.neuralMap.nodes) {
        if (consumer.id === node.id) continue;

        const readsFromThis = consumer.data_in.some(
          flow => flow.source === node.id
        );
        if (!readsFromThis) continue;

        const alreadyExists = node.edges.some(
          e => e.edge_type === 'READS' && e.target === consumer.id
        );
        if (alreadyExists) continue;

        const edge: Edge = {
          target: consumer.id,
          edge_type: 'READS',
          conditional: false,
          async: false,
        };

        node.edges.push(edge);
        this.neuralMap.edges.push({ ...edge });
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

        const sourceNode = this.neuralMap.nodes.find(n => n.id === flow.source);
        if (!sourceNode) continue;

        const alreadyExists = sourceNode.edges.some(
          e => e.edge_type === 'WRITES' && e.target === node.id
        );
        if (alreadyExists) continue;

        const edge: Edge = {
          target: node.id,
          edge_type: 'WRITES',
          conditional: false,
          async: false,
        };

        sourceNode.edges.push(edge);
        this.neuralMap.edges.push({ ...edge });
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
    }

    for (const dep of dependencyNodes) {
      const alreadyExists = moduleNode.edges.some(
        e => e.edge_type === 'DEPENDS' && e.target === dep.id
      );
      if (alreadyExists) continue;

      const edge: Edge = {
        target: dep.id,
        edge_type: 'DEPENDS',
        conditional: false,
        async: false,
      };

      moduleNode.edges.push(edge);
      this.neuralMap.edges.push({ ...edge });
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
    const nodeById = new Map(this.neuralMap.nodes.map(n => [n.id, n]));

    // Step 1: For each function, find its contained sink nodes
    // A "contained" node is one that has a CONTAINS edge path from the function STRUCTURAL node.
    const functionContainedNodes = new Map<string, NeuralMapNode[]>();

    for (const [funcName, funcNodeId] of this.functionRegistry) {
      const funcNode = nodeById.get(funcNodeId);
      if (!funcNode) continue;

      // BFS to find all nodes contained by this function
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
        // Follow CONTAINS edges
        for (const edge of current.edges) {
          if (edge.edge_type === 'CONTAINS' && !visited.has(edge.target)) {
            queue.push(edge.target);
          }
        }
      }
      functionContainedNodes.set(funcNodeId, contained);
    }

    // Step 2: For each function, find sinks (STORAGE, EXTERNAL) in its contained nodes
    // and check if they have tainted data_in from parameter variables
    const sinkTypes = new Set(['STORAGE', 'EXTERNAL']);
    const functionTaintSummaries = new Map<string, {
      funcName: string;
      funcNodeId: string;
      sinks: NeuralMapNode[];
      paramNames: string[];
    }>();

    for (const [funcName, funcNodeId] of this.functionRegistry) {
      const contained = functionContainedNodes.get(funcNodeId) || [];
      const sinks = contained.filter(n => sinkTypes.has(n.node_type));

      if (sinks.length === 0) continue;

      // Extract param names from the function's code_snapshot
      const funcNode = nodeById.get(funcNodeId);
      if (!funcNode) continue;
      // Try the profile's pattern first (language-specific), fall back to JS default
      const jsPattern = /(?:function\s+\w+\s*|(?:async\s+)?)\(([^)]*)\)|(\w+)\s*=>|\w+\s*\(([^)]*)\)\s*\{/;
      const funcAnalysis = funcNode.analysis_snapshot || funcNode.code_snapshot;
      const paramMatch = (this.profile.functionParamPattern
        ? funcAnalysis.match(this.profile.functionParamPattern)
        : null
      ) || funcAnalysis.match(jsPattern);
      let paramNames: string[] = [];
      if (paramMatch) {
        const paramStr = paramMatch[1] || paramMatch[2] || paramMatch[3] || '';
        paramNames = paramStr.split(',').map(p => {
          // Strip default values, TypeScript/Go-style type annotations, spread operators
          let token = p.trim()
            .replace(/\s*=.*$/, '')
            .replace(/\s*:.*$/, '')
            .replace(/\.{3}/, '')
            .replace(/^\*{1,2}/, '');
          // STEP 4 (Java): handle `TypeName varName` and `final TypeName varName` pairs —
          // take only the last whitespace-delimited word as the parameter name.
          // This is gated on whether the profile is Java (detected by language id).
          if (this.profile.id === 'java' && /\s/.test(token)) {
            const parts = token.trim().split(/\s+/);
            token = parts[parts.length - 1];
          }
          return token;
        }).filter(Boolean);
      }

      // Check if any sink's code_snapshot references a parameter
      const sinksReferencingParams = sinks.filter(sink =>
        paramNames.some(p => (sink.analysis_snapshot || sink.code_snapshot).includes(p))
      );

      if (sinksReferencingParams.length > 0) {
        functionTaintSummaries.set(funcName, {
          funcName,
          funcNodeId,
          sinks: sinksReferencingParams,
          paramNames,
        });
      }
    }

    // Step 3: At call sites, if tainted data flows to a function with a vulnerable
    // taint summary, create DATA_FLOW edges from the tainted source to the function's sinks
    for (const node of this.neuralMap.nodes) {
      // Find call sites — nodes that have data_in with tainted=true
      // AND whose code_snapshot calls a function in our summary
      for (const [funcName, summary] of functionTaintSummaries) {
        // Check if this node is a call to the summarized function
        if ((node.analysis_snapshot || node.code_snapshot).match(new RegExp('\\b' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(')) !== null) {
          // Check if the call has any tainted data flowing in
          const hasTaintedInput = node.data_in.some(d => d.tainted);

          if (hasTaintedInput) {
            // Create DATA_FLOW edges from this call node to each sink in the function
            for (const sink of summary.sinks) {
              const alreadyExists = node.edges.some(
                e => e.edge_type === 'DATA_FLOW' && e.target === sink.id
              );
              if (!alreadyExists) {
                const edge: Edge = {
                  target: sink.id,
                  edge_type: 'DATA_FLOW',
                  conditional: false,
                  async: false,
                };
                node.edges.push(edge);
                this.neuralMap.edges.push({ ...edge });
              }
            }
          }

          // Also check: does the call_expression's snapshot itself contain tainted source patterns?
          // This catches cases where the call is: helper(req.query.x) but the node isn't the call itself
          if (this.profile.ingressPattern.test(node.analysis_snapshot || node.code_snapshot)) {
            // Find the INGRESS node for this tainted source
            const ingressNodes = this.neuralMap.nodes.filter(n =>
              n.node_type === 'INGRESS' && n.attack_surface.includes('user_input')
            );
            for (const ingress of ingressNodes) {
              for (const sink of summary.sinks) {
                const alreadyExists = ingress.edges.some(
                  e => e.edge_type === 'DATA_FLOW' && e.target === sink.id
                );
                if (!alreadyExists) {
                  const edge: Edge = {
                    target: sink.id,
                    edge_type: 'DATA_FLOW',
                    conditional: false,
                    async: false,
                  };
                  ingress.edges.push(edge);
                  this.neuralMap.edges.push({ ...edge });
                }
              }
            }
          }
        }
      }
    }

    // Step 4: Mark local_call nodes tainted if their function has a taint summary
    // (meaning the function's body has sinks that reference params — or the function
    // captures tainted outer variables visible in the code_snapshot).
    const allLocalCalls = this.neuralMap.nodes.filter(n => n.node_subtype === 'local_call');
    for (const lc of allLocalCalls) {
      if (lc.data_out.some(d => d.tainted)) continue; // already tainted from args

      // Extract function name from the local_call's code
      for (const [funcName, summary] of functionTaintSummaries) {
        if ((lc.analysis_snapshot || lc.code_snapshot).match(new RegExp('\\b' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(')) !== null) {
          // This local_call invokes a function with a taint summary → mark tainted
          lc.data_out.push({
            name: 'result', source: lc.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
          });
          break;
        }
      }
    }

    // Step 5: Connect local_call return values to consumer sinks.
    // When db.query(makeQuery()), the inner makeQuery() creates a local_call node
    // but the outer db.query() was processed BEFORE the inner call.
    const taintedLocalCalls = this.neuralMap.nodes.filter(n =>
      n.node_subtype === 'local_call' && n.data_out.some(d => d.tainted)
    );
    const sinkNodes = this.neuralMap.nodes.filter(n =>
      n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL'
    );
    for (const lc of taintedLocalCalls) {
      for (const sink of sinkNodes) {
        if ((sink.analysis_snapshot || sink.code_snapshot).includes(lc.label.slice(0, 30)) && sink.id !== lc.id) {
          const alreadyExists = lc.edges.some(e => e.edge_type === 'DATA_FLOW' && e.target === sink.id);
          if (!alreadyExists) {
            const edge: Edge = { target: sink.id, edge_type: 'DATA_FLOW', conditional: false, async: false };
            lc.edges.push(edge);
            this.neuralMap.edges.push({ ...edge });
          }
        }
      }

      // Also: if this local_call's result is stored in a variable (same line),
      // find the INGRESS nodes that can reach it and connect them to internal sinks
      for (const summary of functionTaintSummaries.values()) {
        if ((lc.analysis_snapshot || lc.code_snapshot).includes(summary.funcName + '(')) {
          for (const sink of summary.sinks) {
            const alreadyExists = lc.edges.some(e => e.edge_type === 'DATA_FLOW' && e.target === sink.id);
            if (!alreadyExists) {
              const edge: Edge = { target: sink.id, edge_type: 'DATA_FLOW', conditional: false, async: false };
              lc.edges.push(edge);
              this.neuralMap.edges.push({ ...edge });
            }
          }
        }
      }
    }

    // Step 6: Event emitter taint propagation.
    // Match .emit('event', taintedData) with .on('event', handler) and create
    // DATA_FLOW edges from the emit's tainted args to sinks inside the handler.
    //
    // Pattern: bus.on('search', (term) => { db.query(... + term + ...) })
    //          bus.emit('search', req.query.term)
    //
    // Scan all nodes for .emit() calls with tainted data, then find matching
    // .on() handlers and connect them.
    const emitPattern = /\.emit\s*\(\s*['"](\w+)['"]/;
    const onPattern = /\.on\s*\(\s*['"](\w+)['"]/;

    // Collect all emit calls with their event names
    const emitNodes: Array<{ node: NeuralMapNode; eventName: string }> = [];
    const onNodes: Array<{ node: NeuralMapNode; eventName: string }> = [];

    for (const node of this.neuralMap.nodes) {
      const emitMatch = (node.analysis_snapshot || node.code_snapshot).match(emitPattern);
      if (emitMatch) emitNodes.push({ node, eventName: emitMatch[1] });

      const onMatch = (node.analysis_snapshot || node.code_snapshot).match(onPattern);
      if (onMatch) onNodes.push({ node, eventName: onMatch[1] });
    }

    // For each emit with tainted data, find matching .on handlers and connect
    for (const emit of emitNodes) {
      // Check if emit has tainted data
      const hasTaint = emit.node.data_in.some(d => d.tainted) ||
        this.profile.ingressPattern.test(emit.node.analysis_snapshot || emit.node.code_snapshot);

      if (!hasTaint) continue;

      // Find matching .on handlers
      const matchingHandlers = onNodes.filter(on => on.eventName === emit.eventName);

      for (const handler of matchingHandlers) {
        // Find sinks (STORAGE, EXTERNAL) that are contained by the same
        // parent scope as the .on handler
        const handlerLine = handler.node.line_start;
        // Look for sinks within a reasonable line range after the .on declaration
        const nearbySinks = this.neuralMap.nodes.filter(n =>
          (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
          n.line_start >= handlerLine && n.line_start <= handlerLine + 20
        );

        // Find INGRESS nodes from the emit
        const ingressNodes = this.neuralMap.nodes.filter(n =>
          n.node_type === 'INGRESS' && n.attack_surface.includes('user_input')
        );

        for (const sink of nearbySinks) {
          for (const ingress of ingressNodes) {
            const alreadyExists = ingress.edges.some(
              e => e.edge_type === 'DATA_FLOW' && e.target === sink.id
            );
            if (!alreadyExists) {
              const edge: Edge = { target: sink.id, edge_type: 'DATA_FLOW', conditional: false, async: false };
              ingress.edges.push(edge);
              this.neuralMap.edges.push({ ...edge });
            }
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
      if (!calleeNodeId) continue; // callee not a locally-defined function
      if (calleeNodeId === pending.callerContainerId) continue; // skip self-recursion

      // Avoid duplicate CALLS edges (same caller -> same callee)
      const callerNode = this.neuralMap.nodes.find(n => n.id === pending.callerContainerId);
      if (!callerNode) continue;

      const alreadyExists = callerNode.edges.some(
        e => e.edge_type === 'CALLS' && e.target === calleeNodeId
      );
      if (alreadyExists) continue;

      const edge: Edge = {
        target: calleeNodeId,
        edge_type: 'CALLS',
        conditional: false,
        async: pending.isAsync,
      };

      callerNode.edges.push(edge);
      this.neuralMap.edges.push({ ...edge });
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
  const ctx = new MapperContext(fileName, sourceCode, profile);
  const root = tree.rootNode;

  // Push module-level scope
  ctx.pushScope('module', root);

  // We need to handle scope push/pop manually during walk because
  // walkTree doesn't give us a post-visit hook. Instead, we use
  // the tree cursor for a proper enter/leave traversal.
  walkWithScopes(root, ctx, profile);

  // NOTE: We intentionally do NOT pop the module scope here.
  // The module scope remains on ctx.scopeStack so that callers can use
  // ctx.resolveVariable() on the returned context (e.g., for constant-folding tests).

  // Post-processing: initialize taint markers and detect sensitivity
  initializeTaint(ctx.neuralMap);

  // Post-processing: resolve CALLS edges
  ctx.buildCallsEdges();

  // Post-processing: build DATA_FLOW edges from data_in references
  ctx.buildDataFlowEdges();

  // Post-processing: PASS 2 — inter-procedural taint propagation
  ctx.propagateInterproceduralTaint();

  // Post-processing: build READS, WRITES, DEPENDS edges
  ctx.buildReadsEdges();
  ctx.buildWritesEdges();
  ctx.buildDependsEdges();

  return { map: ctx.neuralMap, ctx };
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
  profile.classifyNode(node, ctx);

  // Recurse into children
  const isStatementContainer = profile.isStatementContainer(node.type);
  for (let i = 0; i < node.childCount; i++) {
    if (isStatementContainer) {
      ctx.lastCreatedNodeId = null;
    }
    const child = node.child(i);
    if (child) {
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
