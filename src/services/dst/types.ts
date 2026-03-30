// Neural Map type definitions for the DST (Deep Structure Transform) pipeline.
// These types define the complete schema for representing code as a security-aware graph.

// ---------------------------------------------------------------------------
// Enums as union types (erasableSyntaxOnly: true forbids enum keyword)
// ---------------------------------------------------------------------------

export type NodeType =
  | 'INGRESS'
  | 'EGRESS'
  | 'TRANSFORM'
  | 'CONTROL'
  | 'AUTH'
  | 'STORAGE'
  | 'EXTERNAL'
  | 'STRUCTURAL'
  | 'META'
  | 'RESOURCE';

export const NODE_TYPES: readonly NodeType[] = [
  'INGRESS', 'EGRESS', 'TRANSFORM', 'CONTROL', 'AUTH',
  'STORAGE', 'EXTERNAL', 'STRUCTURAL', 'META',
] as const;

/** Extended node types including RESOURCE — the 10th type for finite capacity tracking */
export const NODE_TYPES_EXTENDED: readonly NodeType[] = [
  ...NODE_TYPES, 'RESOURCE',
] as const;

export type EdgeType =
  | 'CALLS'
  | 'RETURNS'
  | 'READS'
  | 'WRITES'
  | 'DEPENDS'
  | 'CONTAINS'
  | 'DATA_FLOW';

export const EDGE_TYPES: readonly EdgeType[] = [
  'CALLS', 'RETURNS', 'READS', 'WRITES', 'DEPENDS', 'CONTAINS', 'DATA_FLOW',
] as const;

export type Sensitivity = 'NONE' | 'PII' | 'SECRET' | 'AUTH' | 'FINANCIAL';

// ---------------------------------------------------------------------------
// Core interfaces
// ---------------------------------------------------------------------------

export interface DataFlow {
  /** Name of the data element (e.g. "userId", "req.body") */
  name: string;
  /** Node ID where data originates, or "EXTERNAL" for user input */
  source: string;
  /** Node ID where data flows to (used in data_out for dedup) */
  target?: string;
  /** Type of data (e.g. "string", "object", "Buffer") */
  data_type: string;
  /** Whether this data is user-controlled (taint tracking) */
  tainted: boolean;
  /** Classification of data sensitivity */
  sensitivity: Sensitivity;
}

export interface Edge {
  /** Target node ID this edge points to */
  target: string;
  /** Type of relationship */
  edge_type: EdgeType;
  /** Whether this edge is conditionally taken (inside if/switch) */
  conditional: boolean;
  /** Whether this edge crosses an async boundary (await, .then) */
  async: boolean;
}

export interface NeuralMapNode {
  /** Unique identifier for this node */
  id: string;
  /** Human-readable label (e.g. "app.get('/users/:id')") */
  label: string;
  /** Execution sequence number (order in which nodes appear) */
  sequence: number;
  /** Primary classification */
  node_type: NodeType;
  /** Finer classification (e.g. "http_handler", "sql_query", "file_read") */
  node_subtype: string;
  /** Source language */
  language: string;
  /** Source file path */
  file: string;
  /** Start line in source (1-indexed) */
  line_start: number;
  /** End line in source (1-indexed) */
  line_end: number;
  /** Verbatim code snippet for this node (truncated to ~200 chars for human display) */
  code_snapshot: string;
  /** Full code context for machine analysis (up to 2000 chars, no truncation) */
  analysis_snapshot: string;
  /** Extracted parameter names from the AST walk (avoids post-hoc string parsing) */
  param_names?: string[];
  /** Resolved call chain for this node (e.g. ["db", "query"]) */
  callee_chain?: string[];
  /** The actual algorithm string for crypto verifiers (e.g. "md5", "sha256") */
  algorithm_name?: string;
  /** Data flowing into this node */
  data_in: DataFlow[];
  /** Data flowing out of this node */
  data_out: DataFlow[];
  /** Edges from this node to other nodes */
  edges: Edge[];
  /** Security-relevant surface indicators (e.g. "user_input", "sql_sink") */
  attack_surface: string[];
  /** Trust boundary this node belongs to (e.g. "public", "authenticated", "internal") */
  trust_boundary: string;
  /** Free-form tags for filtering */
  tags: string[];
  /** Arbitrary key-value metadata */
  metadata: Record<string, unknown>;
}

export interface NeuralMap {
  /** All classified nodes in the map */
  nodes: NeuralMapNode[];
  /** Top-level edges (cross-node relationships not captured in node.edges) */
  edges: Edge[];
  /** Path of the source file that was analyzed */
  source_file: string;
  /** The raw source code that was parsed */
  source_code: string;
  /** ISO timestamp when this map was created */
  created_at: string;
  /** Version of the parser/mapper that produced this map */
  parser_version: string;
}

// ---------------------------------------------------------------------------
// Factory / helper
// ---------------------------------------------------------------------------

let _sequenceCounter = 0;
let _sequenceGeneration = 0;

/**
 * Reset the sequence counter (for node ordering within a map).
 * Call between tests or between files. Increments the generation prefix
 * so IDs from previous builds never collide with new ones.
 */
export function resetSequence(): void {
  _sequenceCounter = 0;
  _sequenceGeneration++;
}

/**
 * Advance to the next ID generation. Call this before concurrent builds
 * to ensure auto-generated node IDs don't collide across maps.
 */
export function nextGeneration(): void {
  _sequenceGeneration++;
}

/**
 * Hard reset both counters to zero. Use in determinism tests where
 * you need two builds to produce identical IDs.
 */
export function resetSequenceHard(): void {
  _sequenceCounter = 0;
  _sequenceGeneration = 0;
}

/**
 * Create a NeuralMapNode with sensible defaults. Only `id` and `node_type`
 * are truly required; everything else gets safe empty values.
 *
 * Usage:
 *   const node = createNode({ node_type: 'INGRESS', label: 'POST /login' });
 */
export function createNode(partial: Partial<NeuralMapNode> & { node_type: NodeType }): NeuralMapNode {
  _sequenceCounter += 1;
  return {
    id: partial.id ?? `node_${_sequenceGeneration}_${_sequenceCounter}`,
    label: partial.label ?? '',
    sequence: partial.sequence ?? _sequenceCounter,
    node_type: partial.node_type,
    node_subtype: partial.node_subtype ?? '',
    language: partial.language ?? 'javascript',
    file: partial.file ?? '',
    line_start: partial.line_start ?? 0,
    line_end: partial.line_end ?? 0,
    code_snapshot: partial.code_snapshot ?? '',
    analysis_snapshot: partial.analysis_snapshot ?? partial.code_snapshot ?? '',
    param_names: partial.param_names,
    callee_chain: partial.callee_chain,
    algorithm_name: partial.algorithm_name,
    data_in: partial.data_in ?? [],
    data_out: partial.data_out ?? [],
    edges: partial.edges ?? [],
    attack_surface: partial.attack_surface ?? [],
    trust_boundary: partial.trust_boundary ?? '',
    tags: partial.tags ?? [],
    metadata: partial.metadata ?? {},
  };
}

/**
 * Create an empty NeuralMap shell for a given file.
 */
export function createNeuralMap(sourceFile: string, sourceCode: string): NeuralMap {
  return {
    nodes: [],
    edges: [],
    source_file: sourceFile,
    source_code: sourceCode,
    created_at: new Date().toISOString(),
    parser_version: '0.1.0',
  };
}
