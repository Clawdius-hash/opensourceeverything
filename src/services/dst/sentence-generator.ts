import type { SemanticSentence } from './types.js';
import { fillTemplate } from './sentence-templates.js';

/**
 * Map (nodeType, subtype) pairs to sentence template keys.
 * This is how phoneme classification connects to sentence generation.
 */
const NODE_TYPE_TO_TEMPLATE: Record<string, Record<string, string>> = {
  INGRESS: {
    http_request: 'retrieves-from-source',
    http_param: 'retrieves-from-source',
    cli_input: 'retrieves-from-source',
    env_variable: 'retrieves-from-source',
    file_read: 'retrieves-from-source',
    socket_read: 'retrieves-from-source',
    _default: 'retrieves-from-source',
  },
  STORAGE: {
    sql_query: 'executes-query',
    db_read: 'executes-query',
    db_write: 'executes-query',
    db_stored_proc: 'executes-query',
    file_write: 'calls-method',
    cache_write: 'calls-method',
    _default: 'calls-method',
  },
  TRANSFORM: {
    string_concat: 'string-concatenation',
    codec: 'calls-method',
    format: 'calls-method',
    sanitize: 'calls-method',
    _default: 'calls-method',
  },
  CONTROL: {
    branch: 'gate-conditional',
    loop: 'iterates-over',
    guard: 'gate-conditional',
    _default: 'gate-conditional',
  },
  EXTERNAL: {
    system_exec: 'calls-method',
    http_request: 'calls-method',
    _default: 'calls-method',
  },
  EGRESS: {
    http_response: 'calls-method',
    _default: 'calls-method',
  },
};

/**
 * Look up the template key for a given nodeType and subtype.
 */
export function getTemplateKey(nodeType: string, subtype: string): string {
  const typeMap = NODE_TYPE_TO_TEMPLATE[nodeType];
  if (!typeMap) return 'calls-method';
  return typeMap[subtype] ?? typeMap['_default'] ?? 'calls-method';
}

/**
 * Generate a semantic sentence from classified node data.
 * Deterministic: same inputs always produce the same sentence.
 */
export function generateSentence(
  templateKey: string,
  slots: Record<string, string>,
  lineNumber: number,
  nodeId: string,
  taintClass: SemanticSentence['taintClass'],
): SemanticSentence {
  return {
    text: fillTemplate(templateKey, slots),
    templateKey,
    slots,
    lineNumber,
    nodeId,
    taintClass,
  };
}
