/**
 * DST Generated Verifiers — Batch 017
 * Gap fill: CWEs 1–199 missing from all registries.
 * 33 CWEs total:
 *   A. Deprecated/Category stubs (27) — always hold, no graph pattern
 *   B. Real verifiers (6) — factory-driven graph checks
 *      CWE-13  Password in Config File
 *      CWE-20  Improper Input Validation
 *      CWE-107 Struts Unused Validation Form
 *      CWE-110 Struts Validator Without Form Field
 *      CWE-116 Improper Encoding/Escaping of Output
 *      CWE-119 Memory Buffer Bounds
 *      CWE-186 Overly Restrictive Regex
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Compact factory (matches batch_015/016 pattern)
// ---------------------------------------------------------------------------

type BfsCheck = (map: NeuralMap, srcId: string, sinkId: string) => boolean;

function v(
  cweId: string, cweName: string, severity: Severity,
  sourceType: NodeType, sinkType: NodeType,
  bfsCheck: BfsCheck,
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = nodesOfType(map, sourceType);
    const sinks = nodesOfType(map, sinkType);
    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        if (bfsCheck(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: missingDesc, severity,
              description: `${sourceType} at ${src.label} → ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }
    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// BFS shortcuts
const nC: BfsCheck = hasTaintedPathWithoutControl;
const nT: BfsCheck = hasPathWithoutTransform;
const nCi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'CONTROL');
const nTi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'TRANSFORM');

// Safe patterns
const V = /\bvalidate\b|\bcheck\b|\bverif\b|\bassert\b|\bguard\b|\bensure\b/i;
const S = /\bsanitize\b|\bescape\b|\bencode\b|\bfilter\b|\bstrip\b/i;
const E = /\bencrypt\b|\bhash\b|\bcipher\b|\bprotect\b|\bsecure\b|\bDPAPI\b|\bRSA\b/i;
const B = /\bbounds\b|\blength.*check\b|\bindex.*valid\b|\bBuffer\.alloc\b|\bArray\.isArray\b/i;

// ---------------------------------------------------------------------------
// A. Deprecated / Category stubs — always hold, no exploitable graph pattern
// ---------------------------------------------------------------------------

function stub(cweId: string, cweName: string): (map: NeuralMap) => VerificationResult {
  return (_map: NeuralMap): VerificationResult => ({
    cwe: cweId,
    name: cweName,
    holds: true,
    findings: [],
  });
}

export const verifyCWE1 = stub('CWE-1', 'DEPRECATED: Location');
export const verifyCWE2 = stub('CWE-2', '7PK - Environment');
export const verifyCWE3 = stub('CWE-3', 'DEPRECATED: Technology-specific Environment Issues');
export const verifyCWE4 = stub('CWE-4', 'DEPRECATED: J2EE Environment Issues');
export const verifyCWE10 = stub('CWE-10', 'DEPRECATED: ASP.NET Environment Issues');
export const verifyCWE16 = stub('CWE-16', 'Configuration');
export const verifyCWE17 = stub('CWE-17', 'DEPRECATED: Code');
export const verifyCWE18 = stub('CWE-18', 'DEPRECATED: Source Code');
export const verifyCWE19 = stub('CWE-19', 'Data Processing Errors');
export const verifyCWE21 = stub('CWE-21', 'DEPRECATED: Pathname Traversal and Equivalence Errors');
export const verifyCWE60 = stub('CWE-60', 'DEPRECATED: UNIX Path Link Problems');
export const verifyCWE63 = stub('CWE-63', 'DEPRECATED: Windows Path Link Problems');
export const verifyCWE68 = stub('CWE-68', 'DEPRECATED: Windows Virtual File Problems');
export const verifyCWE70 = stub('CWE-70', 'DEPRECATED: Mac Virtual File Problems');
export const verifyCWE71 = stub('CWE-71', "DEPRECATED: Apple '.DS_Store'");
export const verifyCWE92 = stub('CWE-92', 'DEPRECATED: Improper Sanitization of Custom Special Characters');
export const verifyCWE100 = stub('CWE-100', 'DEPRECATED: Technology-Specific Input Validation Problems');
export const verifyCWE101 = stub('CWE-101', 'DEPRECATED: Struts Validation Problems');
export const verifyCWE132 = stub('CWE-132', 'DEPRECATED: Miscalculated Null Termination');
export const verifyCWE133 = stub('CWE-133', 'String Errors');
export const verifyCWE136 = stub('CWE-136', 'Type Errors');
export const verifyCWE137 = stub('CWE-137', 'Data Neutralization Issues');
export const verifyCWE139 = stub('CWE-139', 'DEPRECATED: General Special Element Problems');
export const verifyCWE169 = stub('CWE-169', 'DEPRECATED: Technology-Specific Special Elements');
export const verifyCWE171 = stub('CWE-171', 'DEPRECATED: Cleansing, Canonicalization, and Comparison Errors');
export const verifyCWE189 = stub('CWE-189', 'Category: Numeric Errors');
export const verifyCWE199 = stub('CWE-199', 'Category: Information Management Errors');

// ---------------------------------------------------------------------------
// B. Real verifiers — graph-pattern-based
// ---------------------------------------------------------------------------

// CWE-13: Password stored in plaintext config without encryption transform
export const verifyCWE13 = v(
  'CWE-13', 'ASP.NET Misconfiguration: Password in Configuration File', 'high',
  'STORAGE', 'STORAGE', nTi, E,
  'TRANSFORM (encryption — DPAPI/RSA before storing credentials in config)',
  'Encrypt credentials in configuration files using DPAPI or RSA key containers. Never store plaintext passwords.',
);

// CWE-20: Input flows to processing without validation control
export const verifyCWE20 = v(
  'CWE-20', 'Improper Input Validation', 'high',
  'INGRESS', 'TRANSFORM', nC, V,
  'CONTROL (input validation — type, length, format, range constraints)',
  'Validate all external input at the boundary. Check type, length, format, and range before processing.',
);

// CWE-107: Struts validation form with no matching action — stale config
// Detection: META nodes (config definitions) not connected to STRUCTURAL (action forms)
export const verifyCWE107 = (function () {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const metaNodes = map.nodes.filter(n =>
      n.node_type === 'META' &&
      (n.node_subtype.includes('validation') || n.node_subtype.includes('struts') ||
       n.code_snapshot.match(/\bvalidation\b.*\bform\b|\bform-validation\b|\bvalidator\b/i) !== null)
    );
    const structuralNodes = map.nodes.filter(n => n.node_type === 'STRUCTURAL');
    const structuralLabels = new Set(structuralNodes.map(n => n.label.toLowerCase()));

    for (const meta of metaNodes) {
      // Check if this validation config has a matching structural form
      const hasMatch = meta.edges.some(e =>
        structuralNodes.some(s => s.id === e.target)
      ) || structuralLabels.has(meta.label.toLowerCase());

      if (!hasMatch) {
        findings.push({
          source: nodeRef(meta),
          sink: nodeRef(meta),
          missing: 'STRUCTURAL (matching action form for validation config)',
          severity: 'low',
          description: `Validation form definition at ${meta.label} has no matching Action Form. Stale configuration may mask missing validation.`,
          fix: 'Remove stale validation form definitions or create matching Action Forms. Ensure all current forms have active validation.',
        });
      }
    }

    return { cwe: 'CWE-107', name: 'Struts: Unused Validation Form', holds: findings.length === 0, findings };
  };
})();

// CWE-110: Struts validator defines fields not in the form — config drift
export const verifyCWE110 = (function () {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const metaNodes = map.nodes.filter(n =>
      n.node_type === 'META' &&
      (n.node_subtype.includes('validator') || n.node_subtype.includes('validation') ||
       n.code_snapshot.match(/\bvalidator\b.*\bfield\b|\bfield\b.*\bvalidat/i) !== null)
    );
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const ingressLabels = new Set(ingressNodes.map(n => n.label.toLowerCase()));

    for (const meta of metaNodes) {
      const hasMatchingField = meta.edges.some(e =>
        ingressNodes.some(ing => ing.id === e.target)
      ) || ingressLabels.has(meta.label.toLowerCase());

      if (!hasMatchingField) {
        findings.push({
          source: nodeRef(meta),
          sink: nodeRef(meta),
          missing: 'INGRESS (matching form field for validator rule)',
          severity: 'low',
          description: `Validator at ${meta.label} defines rules for fields not present in the form. New fields may lack validation.`,
          fix: 'Synchronize validator configuration with actual form fields. Remove stale rules and add validation for new fields.',
        });
      }
    }

    return { cwe: 'CWE-110', name: 'Struts: Validator Without Form Field', holds: findings.length === 0, findings };
  };
})();

// CWE-116: Output reaches structured contexts (HTML, SQL, shell, logs) without encoding transform
export const verifyCWE116 = v(
  'CWE-116', 'Improper Encoding or Escaping of Output', 'high',
  'INGRESS', 'EGRESS', nT, S,
  'TRANSFORM (output encoding — context-appropriate escaping before structured output)',
  'Apply context-specific encoding before outputting to HTML, SQL, shell, or log contexts. Use parameterized APIs where possible.',
);

// CWE-119: Memory buffer operations without bounds checking
export const verifyCWE119 = v(
  'CWE-119', 'Improper Restriction of Operations within the Bounds of a Memory Buffer', 'critical',
  'INGRESS', 'STORAGE', nC, B,
  'CONTROL (bounds check — validate index/length before buffer read/write)',
  'Validate all indices and lengths before buffer operations. Use safe APIs that enforce bounds automatically.',
);

// CWE-186: Regex validation exists but is too restrictive — dangerous values bypass
// This is a subtle check: INGRESS reaches TRANSFORM/STORAGE, a CONTROL node exists
// on the path but its code suggests an overly narrow regex (short pattern, no alternation).
export const verifyCWE186 = (function () {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = [...nodesOfType(map, 'TRANSFORM'), ...nodesOfType(map, 'STORAGE')];
    const controls = nodesOfType(map, 'CONTROL');

    // Find CONTROL nodes that use regex validation
    const regexControls = controls.filter(c =>
      c.code_snapshot.match(/\/[^/]+\/|\bnew RegExp\b|\b\.test\b|\b\.match\b|\b\.replace\b.*\/[^/]+\//i) !== null
    );

    for (const ctrl of regexControls) {
      // Heuristic: overly restrictive regex — very short pattern or missing common attack chars
      const codeSnap = ctrl.code_snapshot;
      const regexMatch = codeSnap.match(/\/([^/]{1,15})\//);
      if (regexMatch) {
        const pattern = regexMatch[1];
        // Short regex without alternation or character classes is suspect
        const isNarrow = pattern.length < 10 && !pattern.includes('|') && !pattern.includes('[');
        if (isNarrow) {
          // Check if this control sits between an ingress and a sink
          for (const src of ingress) {
            for (const sink of sinks) {
              if (src.id === sink.id || src.id === ctrl.id || sink.id === ctrl.id) continue;
              const srcReachesCtrl = src.edges.some(e => e.target === ctrl.id) ||
                ctrl.edges.some(e => e.target === sink.id);
              if (srcReachesCtrl) {
                findings.push({
                  source: nodeRef(src),
                  sink: nodeRef(sink),
                  missing: 'CONTROL (comprehensive regex — pattern too narrow to catch all malicious input)',
                  severity: 'medium',
                  description: `Regex validation at ${ctrl.label} appears overly restrictive (pattern: /${pattern}/). Dangerous values may bypass the filter and reach ${sink.label}.`,
                  fix: 'Broaden the validation regex to cover all known attack vectors. Use allowlists rather than denylists where possible.',
                });
                break; // One finding per control is enough
              }
            }
            if (findings.length > 0) break;
          }
        }
      }
    }

    return { cwe: 'CWE-186', name: 'Overly Restrictive Regular Expression', holds: findings.length === 0, findings };
  };
})();

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_017_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Deprecated / Category stubs
  'CWE-1': verifyCWE1, 'CWE-2': verifyCWE2, 'CWE-3': verifyCWE3, 'CWE-4': verifyCWE4,
  'CWE-10': verifyCWE10, 'CWE-16': verifyCWE16, 'CWE-17': verifyCWE17, 'CWE-18': verifyCWE18,
  'CWE-19': verifyCWE19, 'CWE-21': verifyCWE21, 'CWE-60': verifyCWE60, 'CWE-63': verifyCWE63,
  'CWE-68': verifyCWE68, 'CWE-70': verifyCWE70, 'CWE-71': verifyCWE71, 'CWE-92': verifyCWE92,
  'CWE-100': verifyCWE100, 'CWE-101': verifyCWE101, 'CWE-132': verifyCWE132, 'CWE-133': verifyCWE133,
  'CWE-136': verifyCWE136, 'CWE-137': verifyCWE137, 'CWE-139': verifyCWE139, 'CWE-169': verifyCWE169,
  'CWE-171': verifyCWE171, 'CWE-189': verifyCWE189, 'CWE-199': verifyCWE199,
  // Real verifiers
  'CWE-13': verifyCWE13, 'CWE-20': verifyCWE20, 'CWE-107': verifyCWE107,
  'CWE-110': verifyCWE110, 'CWE-116': verifyCWE116, 'CWE-119': verifyCWE119,
  'CWE-186': verifyCWE186,
};
