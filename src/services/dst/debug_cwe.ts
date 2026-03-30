import { scanCode, initDST } from './scan.js';

await initDST();
const code = (await import('fs')).readFileSync('C:/Users/pizza/AppData/Local/Temp/redteam_g2/cwe190_vuln.js', 'utf8');
const result = await scanCode(code, 'cwe190_vuln.js');

if (result.neuralMap) {
  console.log('Nodes:');
  for (const n of result.neuralMap.nodes) {
    console.log(`  [${n.id}] [${n.node_type}/${n.node_subtype}] ${n.label} L${n.line_start}`);
    console.log(`    code: ${JSON.stringify(n.code_snapshot.slice(0,100))}`);
    if (n.edges.length > 0) {
      for (const e of n.edges) {
        const tgt = result.neuralMap.nodes.find((x: any) => x.id === e.target);
        console.log(`    -> ${e.edge_type} to [${tgt?.node_type}] ${tgt?.label}`);
      }
    }
  }
}
