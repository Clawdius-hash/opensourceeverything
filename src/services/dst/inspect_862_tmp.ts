import { buildNeuralMap } from './mapper';
import { readFileSync } from 'fs';
import { Parser, Language } from 'web-tree-sitter';
import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';
import { javascriptProfile } from './profiles/javascript';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../../../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  const lang = await Language.load(wasmBuffer);
  parser.setLanguage(lang);

  const code = readFileSync('C:/tmp/test_862_safe.js', 'utf8');
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, 'test.js', javascriptProfile);
  
  const AUTHZ862 = /\b(requireAuth|isAuthenticated|checkAuth|authorize|verifyToken|passport|jwt\.verify|session\.user|req\.user|hasPermission|checkPermission|checkAccess|isAuthorized|requireRole|hasRole|can\s*\(\s*['"]|ability|policy|guard|rbac|abac|acl|permission|isOwner|ownerCheck|belongsTo|createdBy|userId\s*===|user\.id\s*===|currentUser\.id)\b/i;
  
  // Find the STORAGE sink
  const sink = map.nodes.find(n => n.node_type === 'STORAGE' && n.node_subtype.includes('write'));
  if (!sink) { console.log("No sink found!"); return; }
  console.log("SINK:", sink.id, sink.label, `L${sink.line_start}-${sink.line_end}`);
  
  // Find direct parent scopes
  const parentScopes = map.nodes.filter(n =>
    (n.node_type === 'STRUCTURAL' && (n.node_subtype === 'function' || n.node_subtype === 'route_def')) &&
    n.edges.some(e => e.edge_type === 'CONTAINS' && e.target === sink.id)
  );
  console.log("\nDirect parent scopes of sink:");
  for (const scope of parentScopes) {
    console.log(`  ${scope.id} ${scope.node_subtype} L${scope.line_start}-${scope.line_end} | ${scope.label.substring(0,60)}`);
    console.log(`  Code (first 100): ${scope.code_snapshot.substring(0,100)}`);
    console.log(`  AUTHZ match on scope code: ${AUTHZ862.test(scope.code_snapshot)}`);
    
    // Children
    const scopeChildren = scope.edges
      .filter(e => e.edge_type === 'CONTAINS')
      .map(e => map.nodes.find(n => n.id === e.target))
      .filter(n => n != null);
    for (const child of scopeChildren) {
      console.log(`    child: ${child!.id} ${child!.node_type}/${child!.node_subtype} | ${child!.label.substring(0,50)}`);
      console.log(`    child AUTHZ match: ${AUTHZ862.test(child!.code_snapshot)}`);
    }
    
    // route_def wrapping the scope
    const routeDefsWrappingScope = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'route_def' &&
      n.line_start <= scope.line_start && n.line_end >= scope.line_end
    );
    console.log(`  Route defs wrapping scope: ${routeDefsWrappingScope.length}`);
    for (const rd of routeDefsWrappingScope) {
      console.log(`    rd: ${rd.id} L${rd.line_start}-${rd.line_end}`);
      console.log(`    rd code (100): ${rd.code_snapshot.substring(0,100)}`);
      console.log(`    rd AUTHZ match: ${AUTHZ862.test(rd.code_snapshot)}`);
    }
  }
  
  // route_defs covering sink
  const routeDefsCoveringSink = map.nodes.filter(n =>
    n.node_type === 'STRUCTURAL' && n.node_subtype === 'route_def' &&
    n.line_start <= sink.line_start && n.line_end >= sink.line_end
  );
  console.log(`\nRoute defs covering sink: ${routeDefsCoveringSink.length}`);
  for (const rd of routeDefsCoveringSink) {
    console.log(`  rd: ${rd.id} L${rd.line_start}-${rd.line_end}`);
    console.log(`  rd code (100): ${rd.code_snapshot.substring(0,100)}`);
    console.log(`  rd AUTHZ match: ${AUTHZ862.test(rd.code_snapshot)}`);
  }
}
main().catch(console.error);
