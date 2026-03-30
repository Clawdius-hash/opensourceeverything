/**
 * Debug: dump tree-sitter structure for the for loop
 */
import { Parser, Language } from 'web-tree-sitter';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function dumpNode(node: any, indent: number = 0): void {
  const pad = ' '.repeat(indent);
  const text = node.text.length > 60 ? node.text.slice(0, 57) + '...' : node.text;
  console.log(`${pad}${node.type} [${node.startPosition.row+1}:${node.startPosition.column}] "${text}"`);
  for (let i = 0; i < node.childCount; i++) {
    dumpNode(node.child(i), indent + 2);
  }
}

async function main() {
  const code = `
class Test {
  void bad() {
    int count = 10;
    for (int i = 0; i < count; i++) {
      System.out.println("Hello");
    }
  }
}`;

  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../../../node_modules/tree-sitter-java/tree-sitter-java.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  const lang = await Language.load(wasmBuffer);
  parser.setLanguage(lang);

  const tree = parser.parse(code);

  // Find the for_statement node
  function findForStatement(node: any): any {
    if (node.type === 'for_statement') return node;
    for (let i = 0; i < node.childCount; i++) {
      const result = findForStatement(node.child(i));
      if (result) return result;
    }
    return null;
  }

  const forNode = findForStatement(tree.rootNode);
  if (forNode) {
    console.log('\n=== FOR STATEMENT STRUCTURE ===\n');
    dumpNode(forNode);
    console.log('\n=== NAMED FIELDS ===\n');
    const condition = forNode.childForFieldName('condition');
    console.log('condition:', condition?.type, condition?.text);
    const init = forNode.childForFieldName('init');
    console.log('init:', init?.type, init?.text);
    const update = forNode.childForFieldName('update');
    console.log('update:', update?.type, update?.text);
    const body = forNode.childForFieldName('body');
    console.log('body:', body?.type, body?.text?.slice(0, 50));
  }

  // Now test with the Juliet-style for loop: for (i = 0; i < count; i++)
  const code2 = `
class Test {
  void bad() {
    int count = 10;
    int i = 0;
    for (i = 0; i < count; i++) {
      System.out.println("Hello");
    }
  }
}`;

  const tree2 = parser.parse(code2);
  const forNode2 = findForStatement(tree2.rootNode);
  if (forNode2) {
    console.log('\n=== JULIET-STYLE FOR STATEMENT STRUCTURE ===\n');
    dumpNode(forNode2);
    console.log('\n=== NAMED FIELDS ===\n');
    const condition = forNode2.childForFieldName('condition');
    console.log('condition:', condition?.type, condition?.text);
    const init = forNode2.childForFieldName('init');
    console.log('init:', init?.type, init?.text);
    const update = forNode2.childForFieldName('update');
    console.log('update:', update?.type, update?.text);
  }
}

main().catch(console.error);
