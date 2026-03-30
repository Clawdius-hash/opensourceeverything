/**
 * Debug: trace CWE-606 logic step by step
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { resetSequence } from './types';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

  const loopNodes = map.nodes.filter((n: any) =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STRUCTURAL' ||
     (n.node_type === 'CONTROL' && n.node_subtype === 'loop')) &&
    LOOP_CONDITION.test(n.analysis_snapshot || n.code_snapshot)
  );

  console.log(`\nLoop nodes: ${loopNodes.length}`);
  for (const loop of loopNodes) {
    const code606 = loop.analysis_snapshot || loop.code_snapshot;
    const isBoundsSafe = BOUNDS_SAFE.test(code606);
    const isCapped = CAPPED.test(code606);
    const hasTaintedInput = loop.data_in.some((d: any) => d.tainted);
    const hasTag = loop.tags?.includes('tainted_loop_bound');

    // Check containing branch
    const containingBranch = map.nodes.find((n: any) =>
      n.node_type === 'CONTROL' && n.node_subtype === 'branch' &&
      n.line_start < loop.line_start && n.line_end >= loop.line_end &&
      /\b\w+\s*(?:<=?|>=?)\s*\d+/.test(n.analysis_snapshot || n.code_snapshot)
    );

    console.log(`\n  ${loop.id} CONTROL/loop "${loop.label}" L${loop.line_start}-${loop.line_end}`);
    console.log(`    LOOP_CONDITION match: ${LOOP_CONDITION.test(code606)}`);
    console.log(`    BOUNDS_SAFE: ${isBoundsSafe}`);
    console.log(`    CAPPED: ${isCapped}`);
    console.log(`    tainted_input: ${hasTaintedInput}`);
    console.log(`    tainted_tag: ${hasTag}`);
    console.log(`    containingBranch: ${containingBranch ? containingBranch.id + ' L' + containingBranch.line_start + '-' + containingBranch.line_end : 'NONE'}`);
    if (containingBranch) {
      console.log(`    branch code: ${(containingBranch.analysis_snapshot || containingBranch.code_snapshot).slice(0, 80)}`);
    }
    console.log(`    filtered by BOUNDS_SAFE or CAPPED: ${isBoundsSafe || isCapped}`);
  }

  // Check ingress nodes
  const ingress = map.nodes.filter((n: any) => n.node_type === 'INGRESS');
  console.log(`\nIngress nodes: ${ingress.length}`);
  for (const src of ingress) {
    console.log(`  ${src.id} "${src.label.slice(0,50)}" L${src.line_start}`);
  }
}

main().catch(console.error);
