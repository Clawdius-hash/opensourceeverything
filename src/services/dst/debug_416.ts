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
const DEREF_RE = /\->\w+|\*\s*\w+|\.\w+\s*[\(\[]|\[\s*\d+\s*\]/;

console.log('freeNodes:');
for (const n of map.nodes) {
  if ((n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') && FREE_RE.test(n.code_snapshot)) {
    console.log(`  [${n.node_type}/${n.node_subtype}] L${n.line_start} seq=${n.sequence}`);
    console.log(`    code: ${JSON.stringify(n.code_snapshot.slice(0,100))}`);
  }
}

console.log('\nderefNodes:');
for (const n of map.nodes) {
  if ((n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS') && DEREF_RE.test(n.code_snapshot)) {
    console.log(`  [${n.node_type}/${n.node_subtype}] L${n.line_start} seq=${n.sequence}`);
    console.log(`    code: ${JSON.stringify(n.code_snapshot.slice(0,100))}`);
  }
}

const JS_UAF_RE = /\b(?:destroy|release|free)\s*\(\s*(\w+)\s*\)[^}]*\b\1\s*\.\s*\w+\s*\(/;
const MEMBER_DESTROY_UAF_RE = /(\w+)\s*\.\s*(?:destroy|close|end)\s*\(\s*\)[^}]*\b\1\s*\.\s*(?!destroy|close|end)\w+\s*\(/;

console.log('\nPattern3 scan:');
for (const n of map.nodes) {
  if (n.node_type === 'STRUCTURAL') {
    const code = n.code_snapshot;
    const m1 = JS_UAF_RE.test(code);
    const m2 = MEMBER_DESTROY_UAF_RE.test(code);
    if (m1 || m2) {
      console.log(`  MATCH [${n.node_type}/${n.node_subtype}] L${n.line_start} m1=${m1} m2=${m2}`);
      console.log(`    code: ${JSON.stringify(code.slice(0,200))}`);
    } else if (code.includes('destroy') || code.includes('release')) {
      console.log(`  NO_MATCH [${n.node_type}/${n.node_subtype}] L${n.line_start}`);
      console.log(`    code: ${JSON.stringify(code.slice(0,200))}`);
    }
  }
}
