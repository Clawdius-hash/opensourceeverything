/**
 * Debug: manually run CWE-606 logic with logging
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { resetSequence } from './types';
import type { NeuralMap, NeuralMapNode } from './types';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function stripComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
}

function getContainingScopeSnapshots(map: NeuralMap, nodeId: string): string[] {
  const result: string[] = [];
  for (const n of map.nodes) {
    if (n.node_type === 'STRUCTURAL' && (n.node_subtype === 'function' || n.node_subtype === 'route')) {
      const containsTarget = n.edges.some(e => e.edge_type === 'CONTAINS' && e.target === nodeId);
      if (containsTarget) {
        result.push(n.analysis_snapshot || n.code_snapshot);
      }
    }
  }
  return result;
}

async function main() {
  const file = 'C:/Users/pizza/vigil/juliet-java/src/testcases/CWE400_Resource_Exhaustion/s01/CWE400_Resource_Exhaustion__connect_tcp_for_loop_01.java';
  const code = fs.readFileSync(file, 'utf-8');

  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../../../node_modules/tree-sitter-java/tree-sitter-java.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  const lang = await Language.load(wasmBuffer);
  parser.setLanguage(lang);

  const tree = parser.parse(code);
  const { javaProfile } = await import('./profiles/java.js');

  resetSequence();
  const { map } = buildNeuralMap(tree, code, file, javaProfile);

  const LOOP_CONDITION = /\b(for|while|do)\b\s*\(/i;
  const BOUNDS_SAFE = /\b(Math\.min|Math\.max|clamp|MAX_|LIMIT|MAX_ITER|MAX_COUNT|MAX_ITEMS|MAX_LOOP|parseInt.*Math\.min|Number.*Math\.min|limit\s*=|maxItems|maxCount|maxIterations|\.slice\(0,\s*\d|\.substring\(0,\s*\d|if\s*\([^)]*>\s*\d+\s*\)|if\s*\([^)]*<\s*\d+\s*\))\b/i;
  const CAPPED = /\b(cap|limit|bound|clamp|truncate|ceiling|floor|constrain)\b/i;

  const ingress = map.nodes.filter((n: any) => n.node_type === 'INGRESS');

  const loopNodes = map.nodes.filter((n: any) =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STRUCTURAL' ||
     (n.node_type === 'CONTROL' && n.node_subtype === 'loop')) &&
    LOOP_CONDITION.test(n.analysis_snapshot || n.code_snapshot) &&
    !BOUNDS_SAFE.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
    !CAPPED.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  console.log(`\nLoop nodes (filtered): ${loopNodes.length}`);
  for (const loop of loopNodes) {
    console.log(`  ${loop.id} ${loop.node_type}/${loop.node_subtype} "${loop.label}" L${loop.line_start}-${loop.line_end}`);
  }

  console.log(`\nIngress nodes: ${ingress.length}`);

  let findings = 0;
  for (const src of ingress) {
    for (const loop of loopNodes) {
      if (src.id === loop.id) continue;
      let loopHasTaint = false;
      if (loop.node_type === 'CONTROL' && loop.node_subtype === 'loop') {
        loopHasTaint = loop.data_in.some((d: any) => d.tainted) ||
                       loop.tags?.includes('tainted_loop_bound');
      }
      if (!loopHasTaint) continue;

      console.log(`\n  Checking: ${src.id} -> ${loop.id} (loopHasTaint=${loopHasTaint})`);

      const containingBranch = map.nodes.find((n: any) =>
        n.node_type === 'CONTROL' && n.node_subtype === 'branch' &&
        n.line_start < loop.line_start && n.line_end >= loop.line_end &&
        /\b\w+\s*(?:<=?|>=?)\s*\d+/.test(n.analysis_snapshot || n.code_snapshot)
      );
      console.log(`    containingBranch: ${containingBranch ? containingBranch.id + ' L' + containingBranch.line_start : 'NONE'}`);
      if (containingBranch) { console.log('    SKIPPED (bounds in branch)'); continue; }

      const scopeSnaps = getContainingScopeSnapshots(map, loop.id);
      const scopeText = stripComments(scopeSnaps.join('\n'));
      console.log(`    scopeSnaps length: ${scopeSnaps.length}, text length: ${scopeText.length}`);
      console.log(`    BOUNDS_SAFE in scope: ${BOUNDS_SAFE.test(scopeText)}`);
      console.log(`    CAPPED in scope: ${CAPPED.test(scopeText)}`);
      if (BOUNDS_SAFE.test(scopeText) || CAPPED.test(scopeText)) { console.log('    SKIPPED (bounds in scope)'); continue; }

      console.log(`    FINDING!`);
      findings++;
    }
  }

  console.log(`\nTotal findings: ${findings}`);
}

main().catch(console.error);
