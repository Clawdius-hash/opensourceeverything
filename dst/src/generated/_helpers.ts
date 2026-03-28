/**
 * DST Generated Verifiers — Shared Helpers
 * Graph traversal, node filtering, and result types used by all batches.
 */

import type { NeuralMap, NeuralMapNode, NodeType, EdgeType } from '../types';

// ---------------------------------------------------------------------------
// Result types (same shape as verifier.ts exports)
// ---------------------------------------------------------------------------

export interface VerificationResult {
  cwe: string;
  name: string;
  holds: boolean;
  findings: Finding[];
}

export interface Finding {
  source: NodeRef;
  sink: NodeRef;
  missing: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix: string;
}

export interface NodeRef {
  id: string;
  label: string;
  line: number;
  code: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low';

// ---------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------

/**
 * Edge types that represent actual data flow between nodes.
 * CONTAINS is structural containment (function contains statement) and
 * DEPENDS is a dependency relationship — neither represents data movement.
 * BFS for vulnerability path detection should only follow flow edges.
 */
const FLOW_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

export function nodeRef(node: NeuralMapNode): NodeRef {
  return { id: node.id, label: node.label, line: node.line_start, code: node.code_snapshot.slice(0, 200) };
}

export function nodesOfType(map: NeuralMap, type: NodeType): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type);
}

/**
 * BFS: is there a path from source to sink that never passes through a CONTROL node?
 * Uses composite visited keys (nodeId:passedControl) to prevent safe-path pruning.
 * Only follows data-flow edges (DATA_FLOW, CALLS, READS, WRITES, RETURNS) —
 * structural containment (CONTAINS) and dependency (DEPENDS) edges are excluded
 * because they do not represent actual data movement between nodes.
 */
export function hasTaintedPathWithoutControl(map: NeuralMap, sourceId: string, sinkId: string): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedControl: boolean }> = [
    { nodeId: sourceId, passedControl: false },
  ];

  while (queue.length > 0) {
    const { nodeId, passedControl } = queue.shift()!;
    const visitKey = `${nodeId}:${passedControl}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const controlNow = passedControl || node.node_type === 'CONTROL';

    if (nodeId === sinkId) {
      if (!controlNow) return true;
      continue;
    }

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${controlNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, passedControl: controlNow });
      }
    }
  }

  return false;
}

/**
 * BFS: is there a path from source to sink that doesn't pass through any
 * intermediate node of the given type? Source and sink themselves are excluded
 * from the check — only nodes BETWEEN them count as mediators.
 *
 * Use this when the sink (or source) is the SAME node type as the missing mediator,
 * e.g., "INGRESS→TRANSFORM without TRANSFORM" where the sink IS a TRANSFORM.
 * Only follows data-flow edges — CONTAINS/DEPENDS are excluded.
 */
export function hasPathWithoutIntermediateType(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
  intermediateType: NodeType,
): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedType: boolean }> = [
    { nodeId: sourceId, passedType: false },
  ];

  while (queue.length > 0) {
    const { nodeId, passedType } = queue.shift()!;
    const visitKey = `${nodeId}:${passedType}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    if (nodeId === sinkId) {
      if (!passedType) return true;
      continue;
    }

    // Only intermediate nodes (not source, not sink) count as mediators
    const isIntermediate = nodeId !== sourceId && node.node_type === intermediateType;
    const typeNow = passedType || isIntermediate;

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${typeNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, passedType: typeNow });
      }
    }
  }

  return false;
}

/**
 * BFS: is there a path from source to sink that never passes through a TRANSFORM node?
 * Detects missing data transformation (encoding, sanitization, hashing, etc.)
 * Uses composite visited keys to prevent safe-path pruning.
 * Only follows data-flow edges — CONTAINS/DEPENDS are excluded.
 */
export function hasPathWithoutTransform(map: NeuralMap, sourceId: string, sinkId: string): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedTransform: boolean }> = [
    { nodeId: sourceId, passedTransform: false },
  ];

  while (queue.length > 0) {
    const { nodeId, passedTransform } = queue.shift()!;
    const visitKey = `${nodeId}:${passedTransform}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const transformNow = passedTransform || node.node_type === 'TRANSFORM';

    if (nodeId === sinkId) {
      if (!transformNow) return true;
      continue;
    }

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${transformNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, passedTransform: transformNow });
      }
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Generic factory — configurable source, sink, safe pattern
// ---------------------------------------------------------------------------

export function createGenericVerifier(
  cweId: string, cweName: string, severity: Severity,
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
  sourceType: NodeType = 'INGRESS',
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = nodesOfType(map, sourceType);
    const sinks = sinkFilter(map);

    for (const src of sources) {
      for (const sink of sinks) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `User input from ${src.label} reaches ${sink.label} without proper controls. ` +
                `Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}
