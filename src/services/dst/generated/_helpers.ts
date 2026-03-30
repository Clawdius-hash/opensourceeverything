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
 * Unified BFS: is there a path from source to sink that never passes through a
 * "gate" node (a node whose type matches gateType)?
 *
 * @param map         - The neural map to traverse
 * @param sourceId    - Start node ID
 * @param sinkId      - Target node ID
 * @param gateType    - NodeType (or array of NodeTypes) that counts as the gate
 * @param requireTaint - When true, only nodes with tainted data_in count as sources;
 *                       currently unused at the BFS level (callers pre-filter sources)
 *                       but included for API completeness and future use.
 *
 * Uses composite visited keys (nodeId:passedGate) to prevent safe-path pruning —
 * a safe path through the gate must not block exploration of unsafe paths.
 * Uses index-based queue iteration (O(n)) instead of shift() (O(n²)).
 * Only follows data-flow edges — CONTAINS/DEPENDS are excluded.
 */
export function hasPathWithoutGate(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
  gateType: NodeType | NodeType[],
  _requireTaint?: boolean,
): boolean {
  const gateSet: ReadonlySet<NodeType> = Array.isArray(gateType)
    ? new Set(gateType)
    : new Set([gateType]);
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedGate: boolean }> = [
    { nodeId: sourceId, passedGate: false },
  ];
  let head = 0; // index-based dequeue — O(1) instead of shift() O(n)

  while (head < queue.length) {
    const { nodeId, passedGate } = queue[head++];
    const visitKey = `${nodeId}:${passedGate}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const isGateType = gateSet.has(node.node_type);

    // A gate only counts if it actually processes data from the tracked path.
    // A CONTROL named "sanitize" that doesn't touch the tainted variable is NOT a real gate.
    const isEffectiveGate = isGateType && (
      // Gate has tainted OR sensitive data flowing INTO it (it processes the relevant input)
      node.data_in?.some(d => d.tainted || d.sensitivity !== 'NONE') ||
      // OR gate has a DATA_FLOW edge FROM a node on our current path
      // (the data actually passes through this control)
      node.edges?.some(e => e.edge_type === 'DATA_FLOW' && visited.has(`${e.target}:false`))
    );

    const gateNow = passedGate || isEffectiveGate;

    if (nodeId === sinkId) {
      if (!gateNow) return true;
      continue;
    }

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${gateNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, passedGate: gateNow });
      }
    }
  }

  return false;
}

/**
 * BFS: is there a path from source to sink that never passes through a CONTROL node?
 * Delegates to hasPathWithoutGate.
 */
export function hasTaintedPathWithoutControl(map: NeuralMap, sourceId: string, sinkId: string): boolean {
  return hasPathWithoutGate(map, sourceId, sinkId, 'CONTROL');
}

/**
 * Fallback taint check: does the sink node's data_in contain a tainted entry
 * whose source is reachable from sourceId via BFS?
 *
 * This covers cases where the mapper captured taint in data_in entries but
 * did not emit explicit DATA_FLOW edges between the source and the sink.
 * Used as a belt-and-suspenders fallback after hasTaintedPathWithoutControl.
 *
 * Multi-hop: any tainted data_in entry on the sink counts, regardless of
 * which specific source node it names — the fact that `d.tainted === true`
 * means the mapper already decided taint reaches this sink.
 */
export function sinkHasTaintedDataIn(map: NeuralMap, sinkId: string): boolean {
  const sink = map.nodes.find(n => n.id === sinkId);
  if (!sink) return false;
  return sink.data_in.some(d => d.tainted);
}

/**
 * SECOND PASS: Evaluate whether CONTROL nodes on a mediated path are actually
 * effective. Returns an array of "weak control" findings.
 *
 * This is the anti-inversion engine. When a path from INGRESS to SINK passes
 * through a CONTROL node, the first pass says "safe." This function asks:
 * "but IS that control actually safe?"
 *
 * Checks for:
 *   - ReDoS: regex in CONTROL has catastrophic backtracking patterns (CWE-1333)
 *   - Sanitizer collapse: CONTROL strips chars that create new dangerous values (CWE-182)
 *   - User-controlled both sides: auth compares two user-supplied values (CWE-639)
 *   - Dead control: CONTROL is in unreachable code or always-true condition
 *   - Incomplete validation: CONTROL validates one field but not the dangerous one
 */
export interface WeakControlFinding {
  controlNode: NeuralMapNode;
  weakness: string;
  cwe: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
}

// ReDoS-prone regex patterns — exponential backtracking
const REDOS_PATTERNS = [
  /\([^)]*[+*][^)]*\)[+*]/,      // (a+)+ or (a*)*
  /\([^)]*\|[^)]*\)[+*]/,         // (a|b)+ with overlapping
  /\([^)]*[+*][^)]*[+*]\)/,       // nested quantifiers (a+b+)
  /\.[\*\+]\.\*$/,                  // .*.*
  /\([^)]*\\s[+*][^)]*\)[+*]/,    // (\s+)+
];

// Patterns that indicate a control compares user-controlled values on both sides
const BOTH_SIDES_USER_RE = /(?:req\.|params\.|query\.|body\.|input\.|user\.).*(?:===?|!==?).*(?:req\.|params\.|query\.|body\.|input\.|user\.)/;

// Sanitizers that strip/remove characters (could collapse into dangerous values)
const STRIP_SANITIZER_RE = /\.replace\s*\([^,]+,\s*['"`]{2}\s*\)|\.replace\s*\([^,]+,\s*['"`]['"`]\s*\)|stripTags|strip_tags|htmlspecialchars.*ENT_QUOTES/;

export function evaluateControlEffectiveness(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): WeakControlFinding[] {
  const findings: WeakControlFinding[] = [];
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  // Collect CONTROL nodes on paths between source and sink
  const controlsOnPath: NeuralMapNode[] = [];
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; path: string[] }> = [
    { nodeId: sourceId, path: [] },
  ];

  while (queue.length > 0) {
    const { nodeId, path } = queue.shift()!;
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    if (node.node_type === 'CONTROL' && nodeId !== sourceId && nodeId !== sinkId) {
      controlsOnPath.push(node);
    }

    if (nodeId === sinkId) continue;

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      if (!visited.has(edge.target)) {
        queue.push({ nodeId: edge.target, path: [...path, nodeId] });
      }
    }
  }

  // Evaluate each CONTROL node
  for (const ctrl of controlsOnPath) {
    const code = ctrl.code_snapshot;

    // Check 1: ReDoS — regex in this control has catastrophic backtracking
    const regexMatch = code.match(/\/([^/]+)\/[gimsuy]*/);
    if (regexMatch) {
      const regexBody = regexMatch[1];
      for (const pattern of REDOS_PATTERNS) {
        if (pattern.test(regexBody)) {
          findings.push({
            controlNode: ctrl,
            weakness: 'ReDoS: this validation regex has catastrophic backtracking',
            cwe: 'CWE-1333',
            severity: 'high',
            description: `CONTROL at ${ctrl.label} uses regex /${regexBody}/ which is vulnerable to ReDoS. ` +
              `The regex itself IS the denial-of-service vector — an attacker can craft input that causes exponential backtracking.`,
          });
          break;
        }
      }
    }

    // Check 2: Both sides user-controlled — auth comparing user values
    if (BOTH_SIDES_USER_RE.test(code)) {
      findings.push({
        controlNode: ctrl,
        weakness: 'Authorization compares two user-controlled values',
        cwe: 'CWE-639',
        severity: 'critical',
        description: `CONTROL at ${ctrl.label} compares user-supplied values against each other. ` +
          `The attacker controls both sides of the check, making it bypassable.`,
      });
    }

    // Check 3: Sanitizer that strips/removes (could collapse)
    if (STRIP_SANITIZER_RE.test(code)) {
      // Check if the stripped result could be dangerous
      const postStripDanger = /\.replace.*(?:script|on\w+=|javascript:|eval|exec|system)/i;
      if (postStripDanger.test(code) || ctrl.node_subtype.includes('sanitize')) {
        findings.push({
          controlNode: ctrl,
          weakness: 'Sanitizer removes characters — could collapse into dangerous values',
          cwe: 'CWE-182',
          severity: 'medium',
          description: `CONTROL at ${ctrl.label} strips characters from input. ` +
            `If the stripped characters interleave with dangerous patterns (e.g., stripping 'x' from 'sxcxrxixpxt'), ` +
            `the result becomes dangerous after removal.`,
        });
      }
    }

    // Check 4: Always-true condition (dead control)
    const alwaysTrue = /if\s*\(\s*(?:true|1|!0|!!1)\s*\)|if\s*\(\s*['"][^'"]+['"]\s*\)/;
    if (alwaysTrue.test(code)) {
      findings.push({
        controlNode: ctrl,
        weakness: 'Control condition is always true — validation never rejects',
        cwe: 'CWE-561',
        severity: 'critical',
        description: `CONTROL at ${ctrl.label} has a condition that is always true. ` +
          `This validation never actually rejects any input — it provides false safety.`,
      });
    }

    // Check 5: Wrong comparison operator in authorization control
    // Java: == on objects (reference comparison instead of .equals())
    // JS: == instead of === (type coercion bypass)
    const wrongCompare = /(?:==\s*(?:req\.|params\.|query\.|body\.|user\.|role|admin|token|session))|(?:(?:role|admin|token|permission|auth)\s*==\s*[^=])/;
    const hasLooseEquality = wrongCompare.test(code) && !code.includes('===') && !code.includes('.equals(');
    if (hasLooseEquality && (ctrl.node_subtype.includes('auth') || ctrl.node_subtype.includes('validate') ||
        code.match(/\b(role|admin|permission|auth|token|session|user)\b/i))) {
      findings.push({
        controlNode: ctrl,
        weakness: 'Authorization uses loose equality — type coercion bypass possible',
        cwe: 'CWE-597',
        severity: 'high',
        description: `CONTROL at ${ctrl.label} uses loose equality (==) in a security comparison. ` +
          `Type coercion can bypass the check (e.g., 0 == "" == false == null in JS, reference vs value in Java).`,
      });
    }

    // Check 6: Permissive regex in validation control — missing anchors
    if (regexMatch) {
      const regexBody = regexMatch[1];
      const hasStartAnchor = regexBody.startsWith('^');
      const hasEndAnchor = regexBody.endsWith('$');
      const isSecurityContext = code.match(/\b(valid|check|sanitiz|filter|allow|deny|block|reject|match)\b/i);
      if (isSecurityContext && (!hasStartAnchor || !hasEndAnchor)) {
        // Only flag if the regex has meaningful content (not just .* or empty)
        if (regexBody.length > 3 && !regexBody.match(/^\.\*$|^\.\+$/)) {
          findings.push({
            controlNode: ctrl,
            weakness: 'Validation regex missing anchors — partial match allows bypass',
            cwe: 'CWE-625',
            severity: 'medium',
            description: `CONTROL at ${ctrl.label} uses regex /${regexBody}/ for validation but is missing ` +
              `${!hasStartAnchor && !hasEndAnchor ? 'both ^ and $' : !hasStartAnchor ? 'start anchor ^' : 'end anchor $'} anchors. ` +
              `An attacker can prepend or append malicious content that passes the partial match.`,
          });
        }
      }
    }
  }

  return findings;
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
  let head = 0;

  while (head < queue.length) {
    const { nodeId, passedType } = queue[head++];
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
 * Delegates to hasPathWithoutGate.
 */
export function hasPathWithoutTransform(map: NeuralMap, sourceId: string, sinkId: string): boolean {
  return hasPathWithoutGate(map, sourceId, sinkId, 'TRANSFORM');
}

// ---------------------------------------------------------------------------
// Comment stripping — prevents comments from defeating safe-pattern detection
// ---------------------------------------------------------------------------

/**
 * Strip comments from a code snapshot so that safe-pattern regexes only match
 * actual code, not comments. Handles:
 *   - Single-line comments (// ...) and (# ...) for Python/Ruby/PHP
 *   - Multi-line comments (/* ... *​/)
 *   - Preserves string literals — won't strip // inside "strings" or 'strings'
 *   - Preserves template literals — won't strip // inside `backtick strings`
 */
export function stripComments(code: string): string {
  let result = '';
  let i = 0;
  const len = code.length;

  while (i < len) {
    const ch = code[i];
    const next = i + 1 < len ? code[i + 1] : '';

    // String literals — skip through without stripping
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      result += ch;
      i++;
      while (i < len) {
        if (code[i] === '\\') {
          // Escaped character — consume both
          result += code[i] + (i + 1 < len ? code[i + 1] : '');
          i += 2;
          continue;
        }
        if (code[i] === quote) {
          result += code[i];
          i++;
          break;
        }
        result += code[i];
        i++;
      }
      continue;
    }

    // Multi-line comment: /* ... */
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < len) {
        if (code[i] === '*' && i + 1 < len && code[i + 1] === '/') {
          i += 2;
          break;
        }
        i++;
      }
      result += ' '; // Replace comment with space to avoid token merging
      continue;
    }

    // Single-line comment: // ...
    if (ch === '/' && next === '/') {
      // Skip to end of line
      i += 2;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    // Hash comment: # ... (Python, Ruby, PHP)
    if (ch === '#') {
      // Skip to end of line
      i++;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    result += ch;
    i++;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Scope-aware safe-pattern helper
// ---------------------------------------------------------------------------

/**
 * Returns analysis_snapshots (full context) for all nodes in the same containing scope as nodeId.
 * "Containing scope" = all nodes sharing the same CONTAINS parent in the graph.
 * Fixes the #1 systemic FP: safe patterns (DOMPurify, parameterized queries, etc.)
 * applied on prior lines are invisible when checking only the sink node itself.
 *
 * V4-D: Uses analysis_snapshot (full 2000-char context, set by V4-A) instead of
 * code_snapshot (200-char truncated display string), so safe-pattern checks on
 * larger functions can see the full surrounding code context.
 */
export function getContainingScopeSnapshots(map: NeuralMap, nodeId: string): string[] {
  const snapshots: string[] = [];
  const targetNode = map.nodes.find(n => n.id === nodeId);
  if (!targetNode) return snapshots;

  // Find the parent STRUCTURAL node that contains this node
  const parentEdge = map.edges.find(e => e.edge_type === 'CONTAINS' && e.target === nodeId);
  if (!parentEdge) {
    // No CONTAINS parent: return the node's own full-context snapshot
    return [targetNode.analysis_snapshot || targetNode.code_snapshot];
  }

  // Get all siblings (nodes contained by the same parent) — use analysis_snapshot for full context
  const siblings = map.edges
    .filter(e => e.edge_type === 'CONTAINS' && e.source === parentEdge.source)
    .map(e => map.nodes.find(n => n.id === e.target))
    .filter(Boolean)
    .map(n => n!.analysis_snapshot || n!.code_snapshot);

  return siblings;
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
          // V4-D: check scope snapshots (analysis_snapshot) so safe patterns on prior lines are visible
          const scopeSnaps = getContainingScopeSnapshots(map, sink.id);
          const combinedScope = stripComments(scopeSnaps.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
          if (!safePattern.test(combinedScope)) {
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
