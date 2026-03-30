import { buildNeuralMap } from './mapper.js';
import { pythonProfile } from './profiles/python.js';
import { Parser, Language } from 'web-tree-sitter';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

async function main() {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  await Parser.init();
  const parser = new Parser();
  let wasmPath = path.resolve(__dirname, '../../../node_modules/tree-sitter-python/tree-sitter-python.wasm');
  const lang = await Language.load(wasmPath);
  parser.setLanguage(lang);

  const code = fs.readFileSync('C:/Users/pizza/vigil/DSVW/dsvw.py', 'utf-8');
  const tree = parser.parse(code);
  const nm = buildNeuralMap('dsvw.py', code, pythonProfile, tree);
  
  console.log('Total nodes:', nm.nodes.length);
  
  // Find INGRESS
  const ingress = nm.nodes.filter(n => n.node_type === 'INGRESS');
  console.log('INGRESS:', ingress.length);
  ingress.forEach(n => console.log('  ', n.id, n.label.slice(0, 60), 'L' + n.line_start));
  
  // Find EGRESS
  const egress = nm.nodes.filter(n => n.node_type === 'EGRESS');
  console.log('EGRESS:', egress.length);
  egress.forEach(n => console.log('  ', n.id, n.label.slice(0, 80), 'L' + n.line_start, 'tainted_in:', n.data_in.filter(d => d.tainted).length));
  
  // Find re.sub node
  const reSub = nm.nodes.filter(n => n.label.includes('re.sub'));
  console.log('re.sub nodes:', reSub.length);
  reSub.forEach(n => {
    console.log('  ', n.id, n.label.slice(0, 80), n.node_type, n.node_subtype, 'L' + n.line_start);
    console.log('    tainted_out:', n.data_out.filter(d => d.tainted).length);
    console.log('    data_in:', n.data_in.length, 'tainted_in:', n.data_in.filter(d => d.tainted).length);
    console.log('    edges:', n.edges.map(e => e.edge_type + '->' + e.target).join(', '));
  });
  
  // Check if content augmented assignment has tainted data
  const contentAssign = nm.nodes.filter(n => n.code_snapshot.includes('content +=') && n.node_subtype === 'assignment');
  console.log('content += nodes:', contentAssign.length);
  contentAssign.forEach(n => {
    console.log('  ', n.id, n.label.slice(0, 40), 'L' + n.line_start, 'tainted_out:', n.data_out.filter(d => d.tainted).length);
    console.log('    edges:', n.edges.map(e => e.edge_type + '->' + e.target).join(', '));
  });
  
  // Check self.wfile.write egress
  const writeEgress = nm.nodes.filter(n => n.code_snapshot.includes('self.wfile.write'));
  console.log('wfile.write nodes:', writeEgress.length);
  writeEgress.forEach(n => {
    console.log('  ', n.id, n.label.slice(0, 80), n.node_type, n.node_subtype, 'L' + n.line_start);
    console.log('    data_in:', n.data_in.map(d => d.name + '(tainted:' + d.tainted + ')').join(', '));
    console.log('    edges:', n.edges.map(e => e.edge_type + '->' + e.target).join(', '));
  });
}
main().catch(e => console.error(String(e).slice(0, 1000)));
