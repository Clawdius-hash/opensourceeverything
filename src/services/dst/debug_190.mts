import { buildNeuralMap } from './mapper.js';
import * as fs from 'fs';

const code = fs.readFileSync('C:/Users/pizza/AppData/Local/Temp/redteam_g2/cwe190_vuln.js', 'utf8');
const map = await buildNeuralMap(code, 'javascript');
console.log('All nodes:');
for (const n of map.nodes) {
  console.log(`  [${n.node_type}/${n.node_subtype}] ${n.label} L${n.line_start} | code: ${JSON.stringify(n.code_snapshot.slice(0,80))}`);
  for (const e of n.edges) {
    const target = map.nodes.find(x => x.id === e.target);
    console.log(`    -> edge: ${e.edge_type} to [${target?.node_type}] ${target?.label}`);
  }
}
