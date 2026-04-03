/**
 * Shared verification result types.
 * Single source of truth — used by hand-written verifiers, generated batches, dedup, and scan.
 */

export interface VerificationResult {
  /** CWE identifier */
  cwe: string;
  /** Human-readable name */
  name: string;
  /** Whether the property holds */
  holds: boolean;
  /** Specific findings — empty if property holds */
  findings: Finding[];
}

export interface Finding {
  /** The source node (where tainted data originates) */
  source: NodeRef;
  /** The sink node (where tainted data arrives without control) */
  sink: NodeRef;
  /** What's missing between source and sink */
  missing: string;
  /** Severity */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Plain-language description */
  description: string;
  /** Remediation guidance */
  fix: string;
  /** CWEs collapsed into this finding by source-sink dedup (Layer 2) */
  collapsed_cwes?: string[];
}

export interface NodeRef {
  id: string;
  label: string;
  line: number;
  code: string;
}
