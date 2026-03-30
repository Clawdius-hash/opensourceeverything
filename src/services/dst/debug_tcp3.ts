/**
 * Debug: run DST and print CWE-400/606 findings
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { resetSequence } from './types';
import { verifyAll } from './verifier';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const file = 'C:/Users/pizza/vigil/juliet-java/src/testcases/CWE400_Resource_Exhaustion/s01/CWE400_Resource_Exhaustion__connect_tcp_for_loop_01.java';
  const code = fs.readFileSync(file, 'utf-8');

  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../../../node_modules/tree-sitter-java/tree-sitter-java.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  const lang = await Language.load(wasmBuffer);
  parser.setLanguage(lang);

  const tree = parser.parse(code);
  const { javaProfile } = await import('./profiles/java.js');

  resetSequence();
  const { map } = buildNeuralMap(tree, code, file, javaProfile);

  const results = verifyAll(map);
  for (const r of results) {
    if (r.cwe === 'CWE-400' || r.cwe === 'CWE-606') {
      console.log(`\n=== ${r.cwe}: ${r.name} === holds=${r.holds}`);
      for (const f of r.findings) {
        console.log(`  source: "${f.source.label.slice(0, 60)}" line=${f.source.line}`);
        console.log(`  sink:   "${f.sink.label.slice(0, 60)}" line=${f.sink.line}`);
        console.log(`  desc:   ${f.description.slice(0, 150)}`);
        console.log();
      }
    }
  }
}

main().catch(console.error);
