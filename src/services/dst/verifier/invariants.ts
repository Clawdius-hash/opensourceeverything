import type { NeuralMap, NeuralMapNode } from '../types.js';

export interface InvariantViolation {
  code: string;
  severity: 'error' | 'warning';
  message: string;
  nodeIds?: string[];
}

export function checkMapInvariants(map: NeuralMap): InvariantViolation[] {
  const violations: InvariantViolation[] = [];
  const nodeIndex = new Map<string, NeuralMapNode>(map.nodes.map(n => [n.id, n]));

  // INV-1: Every node ID must be unique
  if (nodeIndex.size !== map.nodes.length) {
    const seen = new Map<string, number>();
    const dupes: string[] = [];
    for (const n of map.nodes) {
      const count = (seen.get(n.id) ?? 0) + 1;
      seen.set(n.id, count);
      if (count === 2) dupes.push(n.id);
    }
    violations.push({
      code: 'UNIQUE_IDS',
      severity: 'error',
      message: `Duplicate node IDs found: ${dupes.join(', ')}`,
      nodeIds: dupes,
    });
  }

  // INV-2: Every edge target must reference an existing node
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      if (!nodeIndex.has(edge.target)) {
        violations.push({
          code: 'EDGE_TARGET_EXISTS',
          severity: 'error',
          message: `Node "${node.id}" has edge targeting non-existent node "${edge.target}"`,
          nodeIds: [node.id],
        });
      }
    }
  }

  // INV-3: DATA_FLOW edges should have matching data_in/data_out entries
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      if (edge.edge_type !== 'DATA_FLOW') continue;
      const targetNode = nodeIndex.get(edge.target);
      if (!targetNode) continue; // Already caught by INV-2
      const hasMatchingDataIn = targetNode.data_in.some(d => d.source === node.id);
      if (!hasMatchingDataIn) {
        violations.push({
          code: 'DATA_FLOW_CONSISTENCY',
          severity: 'warning',
          message: `Node "${node.id}" has DATA_FLOW edge to "${edge.target}" but target has no data_in from source`,
          nodeIds: [node.id, edge.target],
        });
      }
    }
  }

  // INV-4: No node should be both INGRESS and CONTROL type
  // node_type is a single value, so this checks for nodes tagged in attack_surface
  // or metadata that contradict their primary type
  for (const node of map.nodes) {
    if (node.node_type === 'INGRESS' && node.tags.includes('control')) {
      violations.push({
        code: 'TYPE_CONFLICT',
        severity: 'warning',
        message: `Node "${node.id}" is INGRESS but tagged as control — possible misclassification`,
        nodeIds: [node.id],
      });
    }
    if (node.node_type === 'CONTROL' && node.tags.includes('ingress')) {
      violations.push({
        code: 'TYPE_CONFLICT',
        severity: 'warning',
        message: `Node "${node.id}" is CONTROL but tagged as ingress — possible misclassification`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-5: CONTROL nodes should have non-empty code_snapshot
  for (const node of map.nodes) {
    if (node.node_type === 'CONTROL' && !node.code_snapshot.trim()) {
      violations.push({
        code: 'CONTROL_SNAPSHOT_EMPTY',
        severity: 'warning',
        message: `CONTROL node "${node.id}" has empty code_snapshot — breaks evaluateControlEffectiveness`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-6: STRUCTURAL function nodes should have at least one CONTAINS edge
  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL') continue;
    const hasContains = node.edges.some(e => e.edge_type === 'CONTAINS');
    if (!hasContains) {
      violations.push({
        code: 'STRUCTURAL_MISSING_CONTAINS',
        severity: 'warning',
        message: `STRUCTURAL node "${node.id}" has no CONTAINS edges — children are orphaned from scope analysis`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-7: Every non-STRUCTURAL, non-META node should have at least one edge
  for (const node of map.nodes) {
    if (node.node_type === 'STRUCTURAL' || node.node_type === 'META') continue;
    if (node.edges.length === 0) {
      violations.push({
        code: 'ORPHAN_NODE',
        severity: 'warning',
        message: `${node.node_type} node "${node.id}" has zero edges — broken mapper output`,
        nodeIds: [node.id],
      });
    }
  }

  return violations;
}
