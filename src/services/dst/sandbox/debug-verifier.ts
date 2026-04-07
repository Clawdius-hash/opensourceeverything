import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import { verifyAll } from '../verifier/index.js';
import * as fs from 'fs';
import * as path from 'path';

const file = process.argv[2] ?? 'BenchmarkTest01877.java';
const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';

async function main() {
  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(
    path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/, '$1'),
    '../../../../node_modules/tree-sitter-java/tree-sitter-java.wasm'
  );
  const lang = await Language.load(fs.readFileSync(wasmPath));
  parser.setLanguage(lang);
  const javaMod = await import('../profiles/java.js');
  const javaProfile = javaMod.default ?? javaMod.javaProfile ?? javaMod.profile;

  const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
  resetSequence();
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, file, javaProfile);
  tree.delete();

  console.log('Story length:', map.story?.length || 0);

  // Check reconciled sentences
  for (const s of map.story || []) {
    if ((s as any).reconciled) {
      console.log('RECONCILED:', s.taintClass, s.text.substring(0, 80));
    }
  }

  const results = verifyAll(map, 'java');
  const cwe89 = results.find(r => r.cwe === 'CWE-89');
  console.log('\nCWE-89 holds:', cwe89?.holds, 'findings:', cwe89?.findings?.length);
  if (cwe89?.findings?.length) {
    for (const f of cwe89.findings) {
      console.log('  Finding:', f.description?.substring(0, 150));
      console.log('  Via:', (f as any).via);
    }
  }
}
main().catch(e => { console.error(e); process.exit(1); });
