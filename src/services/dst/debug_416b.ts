import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper.js';
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

const code = fs.readFileSync('C:/Users/pizza/AppData/Local/Temp/redteam_g2/cwe416_vuln.js', 'utf8');
const tree = parser.parse(code);
const { map } = buildNeuralMap(tree, code, 'cwe416_vuln.js', javascriptProfile);

const FREE_RE = /\b(free|cfree|kfree|vfree|g_free|delete\s+\w+|delete\s*\[\s*\]\s*\w+|HeapFree|GlobalFree|LocalFree|CoTaskMemFree|fclose|closesocket|CloseHandle)\s*\(|[\w$]+\.(destroy|release|dispose|close|end|terminate|shutdown)\s*\(/i;

const freeNodes = map.nodes.filter(n =>
  (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
  FREE_RE.test(n.code_snapshot)
);

console.log('freeNodes:', freeNodes.length);
for (const n of freeNodes) {
  console.log(`  [${n.node_type}/${n.node_subtype}] L${n.line_start} seq=${n.sequence} code=${JSON.stringify(n.code_snapshot)}`);
  
  // Simulate Approach B
  const FREE_SUBJECT_RE = /(?:(?:destroy|release|free)\s*\(\s*(\w+)\s*\)|(\w+)\s*\.\s*(?:destroy|release|close|end)\s*\()/;
  const m = FREE_SUBJECT_RE.exec(n.code_snapshot);
  console.log(`  subject match:`, m ? { subject: m[1] || m[2] } : null);
  
  if (m) {
    const subject = m[1] || m[2];
    const sharesScope = map.nodes.filter(x => {
      if (x.id === n.id) return false;
      // Check sharesFunctionScope manually
      const parentsA = map.nodes.filter(p => 
        p.node_type === 'STRUCTURAL' && 
        p.edges.some(e => e.edge_type === 'CONTAINS' && e.target === n.id)
      );
      const parentsB = map.nodes.filter(p =>
        p.node_type === 'STRUCTURAL' &&
        p.edges.some(e => e.edge_type === 'CONTAINS' && e.target === x.id)
      );
      return parentsA.some(pa => parentsB.some(pb => pa.id === pb.id));
    });
    const afterFreeWithSubject = sharesScope.filter(x =>
      x.sequence > n.sequence &&
      new RegExp(`\b${subject}\s*\.`).test(x.code_snapshot)
    );
    console.log(`  nodes after with subject '${subject}':`, afterFreeWithSubject.length);
    for (const x of afterFreeWithSubject) {
      console.log(`    [${x.node_type}] seq=${x.sequence} code=${JSON.stringify(x.code_snapshot)}`);
    }
  }
}
