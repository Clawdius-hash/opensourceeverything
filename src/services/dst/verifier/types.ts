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
  /** Proof certificate from the reverse mapper (payload-gen) — optional, added by --prove */
  proof?: ProofCertificate;
}

export interface NodeRef {
  id: string;
  label: string;
  line: number;
  code: string;
}

// ---------------------------------------------------------------------------
// Proof Certificate types — produced by the reverse mapper (payload-gen.ts)
// ---------------------------------------------------------------------------

/** A concrete proof payload with safety metadata */
export interface ProofPayload {
  /** The actual payload string */
  value: string;
  /** The canary string to search for in output */
  canary: string;
  /** Injection context this payload targets */
  context: 'sql_string' | 'sql_numeric' | 'html_body' | 'html_attribute'
         | 'js_string' | 'url_context' | 'shell_concat' | 'shell_quoted'
         | 'ldap_filter' | 'xpath_predicate' | 'xml_entity'
         | 'file_path' | 'log_line' | 'template_expr'
         | 'generic';
  /** Safe for automated execution? */
  execution_safe: boolean;
}

/** How to deliver the payload to the application */
export interface DeliverySpec {
  channel: 'http' | 'stdin' | 'env' | 'file' | 'socket' | 'message_queue' | 'unknown';
  http?: {
    method: string;
    path: string;
    param?: string;
    header?: string;
    cookie?: string;
  };
  /** Payload before encoding for delivery */
  raw_payload: string;
  /** Payload after encoding (URL-encode, Base64, etc.) */
  encoded_payload: string;
}

/** How to verify the payload worked */
export interface OracleDefinition {
  type: 'static' | 'dynamic' | 'hybrid';
  /** Logical argument for why the payload reaches the sink */
  static_proof: string;
  /** What to look for at runtime */
  dynamic_signal?: {
    type: 'content_match' | 'timing' | 'error_pattern' | 'status_code';
    pattern: string;
    positive: boolean;
  };
  /** What the safe (patched) version produces */
  baseline?: string;
}

/** Analysis of the path between source and sink */
export interface PathAnalysis {
  /** Nodes on the path, in order */
  path_node_ids: string[];
  /** TRANSFORM nodes and their effects */
  transforms: Array<{
    node_id: string;
    subtype: string;
    effect: {
      effect: 'encoding' | 'type_coercion' | 'destruction' | 'format_constraint'
            | 'path_normalization' | 'xml_processing' | 'none' | 'unknown';
      payload_action: 'encode_before_delivery' | 'check_if_numeric_only'
                    | 'payload_blocked' | 'embed_in_format' | 'check_traversal_survival'
                    | 'embed_in_xml' | 'pass_through' | 'flag_uncertain';
    };
  }>;
  /** Whether the payload is expected to survive all transforms */
  payload_reaches_sink: boolean;
  /** If false, why not */
  blocked_by?: string;
}

/** The complete proof certificate attached to a Finding */
export interface ProofCertificate {
  primary_payload: ProofPayload;
  variants: ProofPayload[];
  delivery: DeliverySpec;
  oracle: OracleDefinition;
  proof_strength: 'conclusive' | 'strong' | 'indicative';
  path_analysis: PathAnalysis | null;
}
