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
const LOGIN_RE = /\b(login|authenticate|passport\.authenticate|sign\s*in|logIn|createSession|doLogin|bcrypt\.compare|bcrypt\.compareSync)\b/i;
const SUCCESS_PATH_RE = /\bdone\s*\(\s*null\s*,\s*user\b|\bres\.\s*(redirect|json|send)\b|\breq\.login\b|\breq\.logIn\b|\bpassport\.authenticate\b|\breq\.session\.\w+\s*=/i;
const sessionRegenPattern = /\b(regenerate|session\.regenerate|req\.session\.regenerate|session\.destroy|rotateSession|newSession|req\.session\.destroy\s*\(\s*\)\s*.*session)/i;

const authNodes = map.nodes.filter(n =>
  (n.node_type === 'AUTH' ||
   (n.node_type === 'STRUCTURAL' && n.node_subtype === 'route_def') ||
   (n.node_type === 'CONTROL' && BCRYPT_AUTH_RE.test(n.code_snapshot))) &&
  LOGIN_RE.test(n.code_snapshot)
);

const passportStrategies = map.nodes.filter(n =>
  /\bpassport\.use\s*\(\s*['"]login['"]/i.test(n.code_snapshot) ||
  /\bLocalStrategy\b/i.test(n.code_snapshot) ||
  /\bdone\s*\(\s*null\s*,\s*user\b/i.test(n.code_snapshot)
);

const allAuthNodes = [...authNodes, ...passportStrategies];
console.log(`allAuthNodes: ${allAuthNodes.length}`);
for (const n of allAuthNodes) {
  console.log(`  [${n.node_type}] L${n.line_start} code: ${JSON.stringify(n.code_snapshot.slice(0,80))}`);
}

const hasSessionRegen = map.nodes.some(n => sessionRegenPattern.test(n.code_snapshot));
console.log(`hasSessionRegen: ${hasSessionRegen}`);

if (allAuthNodes.length > 0 && !hasSessionRegen) {
  for (const authNode of allAuthNodes) {
    const hasSuccessPath = SUCCESS_PATH_RE.test(authNode.code_snapshot) ||
      map.nodes.some(n =>
        n.line_start >= authNode.line_start &&
        n.line_start <= authNode.line_start + 30 &&
        SUCCESS_PATH_RE.test(n.code_snapshot)
      );
    console.log(`\nAuthNode L${authNode.line_start}: hasSuccessPath=${hasSuccessPath}`);
    const nearbyNodes = map.nodes.filter(n => 
      n.line_start >= authNode.line_start && n.line_start <= authNode.line_start + 30
    );
    for (const nn of nearbyNodes) {
      const matches = SUCCESS_PATH_RE.test(nn.code_snapshot);
      console.log(`  L${nn.line_start} [${nn.node_type}] matches=${matches} code=${JSON.stringify(nn.code_snapshot.slice(0,60))}`);
    }
  }
}
