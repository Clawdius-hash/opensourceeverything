import { buildNeuralMap } from './mapper.js';
import { pythonProfile } from './profiles/python.js';
import * as fs from 'fs';

async function main() {
  const code = fs.readFileSync('C:/Users/pizza/vigil/DSVW/dsvw.py', 'utf-8');
  const nm = await buildNeuralMap('dsvw.py', code, pythonProfile);
  console.log('Total nodes:', nm.nodes.length);
  const ingress = nm.nodes.filter(n => n.node_type === 'INGRESS');
  console.log('INGRESS nodes:');
  ingress.forEach(n => console.log('  ', n.id, n.label.slice(0, 80), n.node_subtype, 'L' + n.line_start));
  console.log('EGRESS nodes:');
  const egress = nm.nodes.filter(n => n.node_type === 'EGRESS');
  egress.forEach(n => console.log('  ', n.id, n.label.slice(0, 80), n.node_subtype, 'L' + n.line_start));
  for (const e of egress) {
    const taintedIn = e.data_in.filter(d => d.tainted);
    if (taintedIn.length > 0) {
      console.log('TAINTED data_in on egress', e.label.slice(0, 40), ':', taintedIn.length);
    }
  }
  const reSub = nm.nodes.filter(n => n.code_snapshot.includes('re.sub'));
  console.log('re.sub nodes:', reSub.length);
  reSub.forEach(n => console.log('  ', n.id, n.label.slice(0, 80), n.node_type, n.node_subtype, 'L' + n.line_start, 'tainted_out:', n.data_out.some(d => d.tainted)));
}
main();
