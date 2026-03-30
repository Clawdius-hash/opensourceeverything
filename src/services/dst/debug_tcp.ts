/**
 * Debug script to dump the neural map for the TCP socket test case
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

  // Load Java profile
  const { javaProfile } = await import('./profiles/java.js');

  resetSequence();
  const { map } = buildNeuralMap(tree, code, file, javaProfile);

  // Count edge types in top-level edges
  const edgeCounts: Record<string, number> = {};
  for (const e of map.edges) {
    edgeCounts[e.edge_type] = (edgeCounts[e.edge_type] || 0) + 1;
  }
  console.log('\n=== TOP-LEVEL EDGE COUNTS ===');
  for (const [type, count] of Object.entries(edgeCounts)) {
    console.log(`  ${type}: ${count}`);
  }

  // Show DATA_FLOW edges from top-level map.edges
  console.log('\n=== TOP-LEVEL DATA_FLOW EDGES ===\n');
  for (const e of map.edges) {
    if (e.edge_type === 'DATA_FLOW') {
      console.log(`  ${(e as any).source} -> ${e.target} (tainted=${(e as any).tainted})`);
    }
  }

  // Show DATA_FLOW edges from per-node edges
  console.log('\n=== PER-NODE DATA_FLOW EDGES ===\n');
  for (const n of map.nodes) {
    for (const e of n.edges) {
      if (e.edge_type === 'DATA_FLOW') {
        console.log(`  ${n.id} (${n.node_type}/${n.node_subtype} "${n.label.slice(0,50)}") -> ${e.target}`);
      }
    }
  }

  // Check: does the for loop at L117 have any tainted data_in?
  const forLoop = map.nodes.find((n: any) => n.id === 'node_2_35');
  if (forLoop) {
    console.log(`\n=== FOR LOOP (node_2_35) at L${forLoop.line_start} ===`);
    console.log(`  type: ${forLoop.node_type}/${forLoop.node_subtype}`);
    console.log(`  data_in: ${forLoop.data_in.length}`);
    for (const d of forLoop.data_in) {
      console.log(`    ${d.name} from ${d.source} tainted=${d.tainted}`);
    }
    console.log(`  data_out: ${forLoop.data_out.length}`);
    console.log(`  edges: ${forLoop.edges.length}`);
    for (const e of forLoop.edges) {
      console.log(`    ${e.edge_type} -> ${e.target}`);
    }
  }

  // Check: count = assignment (tainted) at L60
  const countAssign = map.nodes.find((n: any) => n.id === 'node_2_21');
  if (countAssign) {
    console.log(`\n=== COUNT ASSIGNMENT (node_2_21) at L${countAssign.line_start} ===`);
    console.log(`  type: ${countAssign.node_type}/${countAssign.node_subtype}`);
    console.log(`  data_in: ${countAssign.data_in.length}`);
    for (const d of countAssign.data_in) {
      console.log(`    ${d.name} from ${d.source} tainted=${d.tainted}`);
    }
    console.log(`  data_out: ${countAssign.data_out.length}`);
    for (const d of countAssign.data_out) {
      console.log(`    ${d.name} to ${d.target || 'N/A'} tainted=${d.tainted}`);
    }
    console.log(`  edges: ${countAssign.edges.length}`);
    for (const e of countAssign.edges) {
      console.log(`    ${e.edge_type} -> ${e.target}`);
    }
  }

  // BFS: can we reach node_2_35 (for loop) from any INGRESS node?
  console.log('\n=== BFS REACHABILITY: INGRESS -> FOR LOOP ===\n');
  const ingress = map.nodes.filter((n: any) => n.node_type === 'INGRESS');
  for (const src of ingress) {
    const visited = new Set<string>();
    const queue = [src.id];
    let found = false;
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);
      if (current === 'node_2_35') { found = true; break; }
      const node = map.nodes.find((n: any) => n.id === current);
      if (!node) continue;
      for (const e of node.edges) {
        if (e.edge_type === 'DATA_FLOW' || e.edge_type === 'CONTAINS') {
          if (!visited.has(e.target)) queue.push(e.target);
        }
      }
    }
    console.log(`  ${src.id} (${src.label.slice(0,40)}) -> node_2_35 (for loop): ${found ? 'REACHABLE' : 'UNREACHABLE'} (visited ${visited.size} nodes)`);
  }
}

main().catch(console.error);
