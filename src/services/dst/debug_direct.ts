import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper.js';
import { verifyAll } from './verifier.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

await Parser.init();
const parser = new Parser();
const wasmPath = path.resolve(__dirname, '../../../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm');
const wasmBuffer = fs.readFileSync(wasmPath);
const JavaScript = await Language.load(wasmBuffer);
parser.setLanguage(JavaScript);

const { javascriptProfile } = await import('./profiles/javascript.js');

const cweFile = process.argv[2] || 'C:/Users/pizza/AppData/Local/Temp/redteam_g2/cwe190_vuln.js';
const code = fs.readFileSync(cweFile, 'utf8');
const tree = parser.parse(code);
const { map } = buildNeuralMap(tree, code, path.basename(cweFile), javascriptProfile);

console.log(`\n=== ${path.basename(cweFile)} ===`);
console.log('Nodes:');
for (const n of map.nodes) {
  console.log(`  [${n.id}] [${n.node_type}/${n.node_subtype}] ${n.label} L${n.line_start}`);
  console.log(`    code: ${JSON.stringify(n.code_snapshot.slice(0,100))}`);
  if (n.edges.length > 0) {
    for (const e of n.edges) {
      const tgt = map.nodes.find(x => x.id === e.target);
      console.log(`    -> ${e.edge_type} to [${tgt?.node_type}] ${tgt?.label}`);
    }
  }
}
