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

const code = fs.readFileSync('C:/Users/pizza/AppData/Local/Temp/redteam_g2/cwe384_vuln.js', 'utf8');
const tree = parser.parse(code);
const { map } = buildNeuralMap(tree, code, 'cwe384_vuln.js', javascriptProfile);

const sessionRegenPattern = /\b(regenerate|session\.regenerate|req\.session\.regenerate|session\.destroy|rotateSession|newSession|req\.session\.destroy\s*\(\s*\)\s*.*session)/i;

for (const n of map.nodes) {
  if (sessionRegenPattern.test(n.code_snapshot)) {
    console.log(`MATCH: [${n.node_type}/${n.node_subtype}] L${n.line_start}`);
    console.log(`  code: ${JSON.stringify(n.code_snapshot.slice(0,200))}`);
  }
}
