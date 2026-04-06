/**
 * Sentence Resolution Pass — resolves PENDING taint after inter-procedural analysis.
 * Runs AFTER propagateInterproceduralTaint, BEFORE story assembly.
 *
 * This replaces reconcileSentences + buildReconciliationReason with a clean,
 * single-responsibility module. Instead of reading node.data_out (which couples
 * the sentence layer to the graph layer), it reads functionReturnTaint directly
 * from the inter-procedural analysis results.
 */
import type { SemanticSentence } from './types.js';

interface ResolverContext {
  sentences: SemanticSentence[];
  functionReturnTaint: Map<string, boolean>;
  functionRegistry: Map<string, string>;
  nodeById: Map<string, any>;
}

/**
 * Single forward pass over all sentences. For each PENDING sentence
 * (function call whose return taint was unknown at walk time), resolve
 * the taint using the now-complete functionReturnTaint map.
 *
 * - false  = function proven clean  -> resolve to NEUTRAL
 * - true   = function returns taint -> resolve to TAINTED
 * - undefined = unanalyzed          -> leave as TAINTED (conservative)
 */
export function resolveSentences(ctx: ResolverContext): void {
  for (const sentence of ctx.sentences) {
    // Only resolve sentences that are PENDING (function call returns not yet analyzed)
    if (sentence.taintBasis !== 'PENDING') continue;

    // Find the node associated with this sentence
    const node = ctx.nodeById.get(sentence.nodeId);
    if (!node) continue;

    // Accept local_call/passthrough nodes directly, OR assignment nodes
    // whose code references a local function call
    const isLocalCallNode = node.node_subtype === 'local_call' || node.node_subtype === 'passthrough';
    const isAssignmentNode = node.node_subtype === 'assignment' || node.node_subtype === 'variable';
    if (!isLocalCallNode && !isAssignmentNode) continue;

    // Look up function return taint from the code snapshot
    const snap = node.analysis_snapshot || node.code_snapshot || '';
    for (const [funcName, funcNodeId] of ctx.functionRegistry) {
      if (funcName.includes(':')) continue;
      if (snap.includes(funcName + '(') || snap.includes(funcName + ' (')) {
        const returnTaint = ctx.functionReturnTaint.get(funcNodeId);
        if (returnTaint === false) {
          // Function proven clean — resolve to NEUTRAL
          sentence.reconciled = true;
          sentence.originalTaintClass = sentence.taintClass;
          sentence.taintClass = 'NEUTRAL';
          sentence.reconciliationReason = `Resolved clean: ${funcName} does not return tainted data`;
        } else if (returnTaint === true) {
          // Function returns tainted — keep/set TAINTED
          if (sentence.taintClass !== 'TAINTED') {
            sentence.reconciled = true;
            sentence.originalTaintClass = sentence.taintClass;
            sentence.taintClass = 'TAINTED';
            sentence.reconciliationReason = `Resolved tainted: ${funcName} returns tainted data`;
          }
        }
        // undefined = unanalyzed, leave as TAINTED (conservative)
        break;
      }
    }
  }
}
