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

const BCRYPT_AUTH_RE = /\bbcrypt\.(compare|compareSync|hash|hashSync)\b/i;

console.log('Checking authNodes filter:');
for (const n of map.nodes) {
  const isAuth = n.node_type === 'AUTH';
  const isStructRoute = n.node_type === 'STRUCTURAL' && n.node_subtype === 'route_def';
  const isCtrlBcrypt = n.node_type === 'CONTROL' && BCRYPT_AUTH_RE.test(n.code_snapshot);
  const typeMatch = isAuth || isStructRoute || isCtrlBcrypt;
  
  const LOGIN_RE = /\b(login|authenticate|passport\.authenticate|sign\s*in|logIn|createSession|doLogin|bcrypt\.compare|bcrypt\.compareSync)\b/i;
  const codeMatch = LOGIN_RE.test(n.code_snapshot);
  
  if (typeMatch || codeMatch) {
    console.log(`  [${n.node_type}/${n.node_subtype}] L${n.line_start} typeMatch=${typeMatch} codeMatch=${codeMatch}`);
    console.log(`    code: ${JSON.stringify(n.code_snapshot.slice(0,120))}`);
    if (typeMatch && codeMatch) console.log('    >>> WOULD BE IN authNodes');
  }
}
