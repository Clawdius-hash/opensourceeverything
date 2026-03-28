/**
 * Callee Pattern Database — maps ~100 known JS function/method names
 * to Neural Map node types with subtypes and taint flags.
 *
 * Three lookup strategies:
 *   1. Direct calls: single identifier like fetch, require, eval
 *   2. Member calls: object.method like res.json, fs.readFile, JSON.parse
 *   3. Wildcard member calls: *.method for any-object patterns like .query, .find
 *
 * Usage:
 *   const result = lookupCallee(['res', 'json']);
 *   // { nodeType: 'EGRESS', subtype: 'http_response', tainted: false }
 */

import type { NodeType } from './types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean; // INGRESS sources are auto-tainted
}

// ── Direct calls (single identifier) ──────────────────────────────────────

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // EXTERNAL
  fetch:                  { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  XMLHttpRequest:         { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  eval:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  Function:               { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // TRANSFORM
  parseInt:               { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  parseFloat:             { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  Number:                 { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  String:                 { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  Boolean:                { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  atob:                   { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  btoa:                   { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  encodeURIComponent:     { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  decodeURIComponent:     { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  encodeURI:              { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  decodeURI:              { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  escape:                 { nodeType: 'TRANSFORM',  subtype: 'sanitize',      tainted: false },
  unescape:               { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },

  // STRUCTURAL
  require:                { nodeType: 'STRUCTURAL',  subtype: 'dependency',   tainted: false },

  // CONTROL
  setTimeout:             { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  setInterval:            { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  setImmediate:           { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  clearTimeout:           { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  clearInterval:          { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },

  // EGRESS
  alert:                  { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },

  // EXTERNAL — Web Workers, dynamic code
  Worker:                 { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  SharedWorker:           { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  WebSocket:              { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  EventSource:            { nodeType: 'INGRESS',    subtype: 'stream_read',   tainted: true },

  // STRUCTURAL — Web Workers
  importScripts:          { nodeType: 'STRUCTURAL',  subtype: 'dependency',   tainted: false },

  // EXTERNAL — exec family (child_process destructured)
  exec:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  execSync:               { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  spawn:                  { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  spawnSync:              { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  fork:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
};

// ── Member calls (object.method) ──────────────────────────────────────────
// Key format: "object.method"

const MEMBER_CALLS: Record<string, CalleePattern> = {
  // ── req.* → INGRESS ──
  'req.body':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.params':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.query':            { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.headers':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.cookies':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.get':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.header':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.ip':               { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.path':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.hostname':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.url':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.body':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.params':       { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.query':        { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.headers':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ── res.* → EGRESS ──
  'res.send':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.json':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.render':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.redirect':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.status':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.end':              { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.write':            { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.sendFile':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.download':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.cookie':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.set':              { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.type':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'response.send':        { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'response.json':        { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },

  // ── console.* → EGRESS ──
  'console.log':          { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.error':        { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.warn':         { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.info':         { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.debug':        { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.trace':        { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },

  // ── fs.* → INGRESS (read) / EGRESS (write) ──
  'fs.readFile':          { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.readFileSync':      { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.createReadStream':  { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.readdir':           { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.readdirSync':       { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.stat':              { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.statSync':          { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.writeFile':         { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.writeFileSync':     { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.createWriteStream': { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.appendFile':        { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.appendFileSync':    { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.unlink':            { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.unlinkSync':        { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },

  // ── process.* → INGRESS ──
  'process.env':          { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: false },
  'process.argv':         { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: true },
  'process.stdin':        { nodeType: 'INGRESS',    subtype: 'user_input',    tainted: true },
  'process.exit':         { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── child_process.* → EXTERNAL ──
  'child_process.exec':      { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.execSync':  { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.spawn':     { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.spawnSync': { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.fork':      { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },

  // ── JSON.* → TRANSFORM ──
  'JSON.parse':           { nodeType: 'TRANSFORM',  subtype: 'parse',         tainted: false },
  'JSON.stringify':       { nodeType: 'TRANSFORM',  subtype: 'serialize',     tainted: false },

  // ── Object.* → TRANSFORM (mass assignment vectors) ──
  'Object.assign':        { nodeType: 'TRANSFORM',  subtype: 'mass_assignment', tainted: false },
  'Object.defineProperty':{ nodeType: 'TRANSFORM',  subtype: 'property_def',   tainted: false },
  'Object.create':        { nodeType: 'TRANSFORM',  subtype: 'instantiation',  tainted: false },
  'Object.fromEntries':   { nodeType: 'TRANSFORM',  subtype: 'mass_assignment', tainted: false },

  // ── Promise.* → TRANSFORM (transparent wrappers — taint passes through) ──
  'Promise.resolve':      { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.reject':       { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.all':          { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.race':         { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.allSettled':   { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },

  // ── crypto.* → TRANSFORM ──
  'crypto.createHash':    { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.createHmac':    { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.randomBytes':   { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.createCipheriv':{ nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.createDecipheriv':{ nodeType: 'TRANSFORM',subtype: 'encrypt',       tainted: false },
  'crypto.pbkdf2':        { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.scrypt':        { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },

  // ── bcrypt.* → AUTH ──
  'bcrypt.compare':       { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'bcrypt.hash':          { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'bcrypt.genSalt':       { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },

  // ── jwt.* → AUTH ──
  'jwt.sign':             { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'jwt.verify':           { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'jwt.decode':           { nodeType: 'TRANSFORM',   subtype: 'parse',         tainted: false },
  'jsonwebtoken.sign':    { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'jsonwebtoken.verify':  { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },

  // ── http/https.* → EXTERNAL ──
  'http.request':         { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'http.get':             { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'https.request':        { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'https.get':            { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },

  // ── axios.* → EXTERNAL ──
  'axios.get':            { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.post':           { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.put':            { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.delete':         { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.patch':          { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.request':        { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },

  // ── window.* → EXTERNAL / EGRESS ──
  'window.fetch':         { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'window.open':          { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'window.alert':         { nodeType: 'EGRESS',      subtype: 'display',       tainted: false },

  // ── vm.* → EXTERNAL (code execution sinks) ──
  'vm.runInNewContext':     { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.runInThisContext':    { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.runInContext':        { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.compileFunction':     { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.createContext':       { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // ── Reflect.* → EXTERNAL (meta-programming, can invoke arbitrary code) ──
  'Reflect.apply':          { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'Reflect.construct':      { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // ── navigator.* → EGRESS ──
  'navigator.sendBeacon':   { nodeType: 'EGRESS',     subtype: 'api_call',      tainted: false },

  // ── window.postMessage → EGRESS (cross-origin communication) ──
  'window.postMessage':     { nodeType: 'EGRESS',     subtype: 'ipc',           tainted: false },

  // ── global/globalThis eval aliases ──
  'global.eval':            { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'globalThis.eval':        { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // ── URL.* ──
  'URL.createObjectURL':    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },

  // ── crypto.subtle.* (Web Crypto API) ──
  'crypto.subtle':          { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },

  // ── document.* → EGRESS / INGRESS ──
  'document.write':       { nodeType: 'EGRESS',      subtype: 'xss_sink',      tainted: false },
  'document.writeln':     { nodeType: 'EGRESS',      subtype: 'xss_sink',      tainted: false },
  'document.cookie':      { nodeType: 'INGRESS',     subtype: 'user_input',    tainted: true },
  'document.location':    { nodeType: 'INGRESS',     subtype: 'user_input',    tainted: true },

  // ── Express app.* → STRUCTURAL (route definitions) ──
  'app.get':              { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'app.post':             { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'app.put':              { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'app.delete':           { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'app.patch':            { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'app.use':              { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'app.all':              { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'app.listen':           { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },
  'router.get':           { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'router.post':          { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'router.put':           { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'router.delete':        { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'router.patch':         { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'router.use':           { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'router.all':           { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Fastify
  // ═══════════════════════════════════════════════════════════════════════════
  // Fastify uses (request, reply) convention instead of (req, res)
  // request.body is JSON-parsed by default (no body-parser middleware needed)

  // ── Fastify request.* → INGRESS ──
  // request.body, request.params, request.query, request.headers already defined in Express section above

  // ── Fastify reply.* → EGRESS ──
  'reply.send':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.code':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.status':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.header':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.headers':        { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.type':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.redirect':       { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.serialize':      { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.raw':            { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.hijack':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.setCookie':      { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },

  // ── Fastify request.raw → INGRESS (raw Node.js IncomingMessage) ──
  'request.raw':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ── Fastify instance.* → STRUCTURAL ──
  'fastify.register':     { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'fastify.decorate':     { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'fastify.addHook':      { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'fastify.inject':       { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  'fastify.get':          { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'fastify.post':         { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'fastify.put':          { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'fastify.delete':       { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'fastify.patch':        { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'fastify.all':          { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'fastify.listen':       { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Koa
  // ═══════════════════════════════════════════════════════════════════════════
  // Koa uses a single `ctx` context object — ctx.request for ingress, ctx.response/ctx.body for egress
  // Common pattern: ctx.request.body (via koa-bodyparser), ctx.params (via koa-router)

  // ── Koa ctx.* → INGRESS ──
  'ctx.request':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.params':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.query':            { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.headers':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.cookies':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.get':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.ip':               { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.url':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.path':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.host':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.hostname':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.href':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.origin':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.originalUrl':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ── Koa ctx.* → EGRESS ──
  'ctx.body':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.status':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.type':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.set':              { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.redirect':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.attachment':       { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.throw':            { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },
  'ctx.assert':           { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── Koa ctx.state → used for passing data between middleware ──
  'ctx.state':            { nodeType: 'TRANSFORM',  subtype: 'middleware_state', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Hapi
  // ═══════════════════════════════════════════════════════════════════════════
  // Hapi uses (request, h) — request for ingress, h (response toolkit) for egress

  // ── Hapi request.* → INGRESS (request.params, request.query, request.headers already covered) ──
  'request.payload':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.state':        { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.auth':         { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'request.url':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.path':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.info':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ── Hapi h.* (response toolkit) → EGRESS ──
  'h.response':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.redirect':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.file':               { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.view':               { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.continue':           { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── Hapi server.* → STRUCTURAL ──
  'server.route':         { nodeType: 'STRUCTURAL', subtype: 'route_def',     tainted: false },
  'server.register':      { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'server.auth':          { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'server.ext':           { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'server.decorate':      { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'server.start':         { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Next.js
  // ═══════════════════════════════════════════════════════════════════════════
  // Next.js API routes use (req, res) like Express — but also have App Router patterns
  // App Router: NextRequest/NextResponse, route handlers export GET/POST/etc.

  // ── Next.js NextResponse.* → EGRESS ──
  'NextResponse.json':    { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'NextResponse.redirect':{ nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'NextResponse.rewrite': { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'NextResponse.next':    { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── Next.js req.* (extends IncomingMessage) — already covered by Express patterns ──
  // ── Next.js cookies()/headers() server functions → INGRESS ──
  'nextReq.nextUrl':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.cookies':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.headers':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.url':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.geo':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.ip':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: NestJS
  // ═══════════════════════════════════════════════════════════════════════════
  // NestJS wraps Express/Fastify — uses decorators for route definition but the
  // underlying req/res objects are still Express-style. Key patterns:
  // - @Body(), @Param(), @Query(), @Headers() decorators
  // - Underlying Express req/res available via @Req()/@Res()
  // - NestJS pipes for validation (ValidationPipe, ParseIntPipe)
  // - Guards for auth (@UseGuards)

  // NestJS typically uses Express under the hood, so req.*/res.* already work.
  // But NestJS also has its own response patterns:
  'response.status':      { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'response.redirect':    { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
};

// ── Wildcard member calls (*.method) ──────────────────────────────────────
// Matched when no specific "object.method" key matches.
// Covers database ORMs, array transforms, string methods, etc.

const STORAGE_READ_METHODS = new Set([
  'query', 'find', 'findOne', 'findMany', 'findById', 'findAll',
  'select', 'get', 'count', 'aggregate', 'distinct', 'exec',
  // ORM raw query methods — bypass parameterization
  'raw', 'rawQuery', 'whereRaw', 'havingRaw', 'orderByRaw',
  '$queryRaw', '$queryRawUnsafe',
]);

const STORAGE_WRITE_METHODS = new Set([
  'insert', 'insertOne', 'insertMany', 'create',
  'update', 'updateOne', 'updateMany', 'upsert',
  'delete', 'deleteOne', 'deleteMany', 'remove',
  'save', 'destroy', 'bulkWrite', 'bulkCreate',
  // Prisma raw execute methods — bypass parameterization, perform writes
  '$executeRaw', '$executeRawUnsafe',
]);

const TRANSFORM_CALCULATE_METHODS = new Set([
  'map', 'filter', 'reduce', 'forEach', 'some', 'every',
  'find', 'findIndex', 'flatMap', 'flat',
  'push', 'pop', 'shift', 'unshift', 'splice', 'concat',
  'sort', 'reverse', 'fill', 'copyWithin',
  // Event emitter methods — classified as TRANSFORM so they get nodes in the graph
  'emit', 'on', 'once', 'addListener', 'removeListener',
  // Promise methods — taint flows through .then/.catch/.finally callbacks
  'then', 'catch', 'finally',
]);

const TRANSFORM_FORMAT_METHODS = new Set([
  'toString', 'trim', 'trimStart', 'trimEnd',
  'toLowerCase', 'toUpperCase', 'toLocaleLowerCase', 'toLocaleUpperCase',
  'split', 'join', 'replace', 'replaceAll',
  'slice', 'substring', 'substr',
  'padStart', 'padEnd', 'repeat',
  'charAt', 'charCodeAt', 'codePointAt',
  'normalize', 'localeCompare',
  'toFixed', 'toPrecision', 'toExponential',
  'toISOString', 'toJSON', 'toLocaleString',
]);

// ── Lookup function ───────────────────────────────────────────────────────

/**
 * Look up a callee chain in the pattern database.
 *
 * @param calleeChain - Array of identifiers from getCalleeChain(), e.g. ['res', 'json']
 * @returns Pattern match with nodeType/subtype/tainted, or null if unknown
 *
 * Strategy:
 *   1. Single identifier → check DIRECT_CALLS
 *   2. Two+ identifiers → join first two as "object.method", check MEMBER_CALLS
 *   3. If no member match → check wildcard sets (db methods, transforms)
 *   4. No match → return null
 */
export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  // Strategy 1: Direct call (single identifier)
  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    return null;
  }

  // Strategy 2: Exact member match ("object.method")
  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  // Also try with just the last two segments for deeper chains
  // e.g. ['db', 'collection', 'find'] → try 'collection.find' too
  if (calleeChain.length > 2) {
    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  // Strategy 3: Wildcard method matching (any object)
  // DB storage patterns — only match if NOT already matched as something specific
  if (STORAGE_READ_METHODS.has(methodName)) {
    // Disambiguate: Array.find vs db.find
    // If objectName is a known non-DB object, skip
    if (!isLikelyArrayMethod(objectName, methodName)) {
      return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
    }
  }

  if (STORAGE_WRITE_METHODS.has(methodName)) {
    return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
  }

  // Transform patterns — only if the method name is unambiguous
  if (TRANSFORM_FORMAT_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'format', tainted: false };
  }

  if (TRANSFORM_CALCULATE_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'calculate', tainted: false };
  }

  return null;
}

// Known non-DB object names: HTTP framework objects, generic objects, array-like names.
// If the object name is in this set, it's definitely not a database handle.
const NON_DB_OBJECTS = new Set([
  // Express / HTTP framework objects
  'app', 'router', 'express', 'req', 'res', 'request', 'response',
  'server', 'client', 'http', 'https',
  // Fastify objects
  'fastify', 'reply', 'instance',
  // Koa objects
  'ctx', 'context', 'koaRouter',
  // Hapi objects
  'h', 'toolkit',
  // Next.js objects
  'NextResponse', 'NextRequest', 'nextReq', 'nextRes',
  // NestJS objects
  'controller', 'service', 'guard', 'pipe', 'interceptor', 'module',
  // Generic non-DB
  'this', 'self', 'event', 'e',
  // Array-like variable names
  'arr', 'array', 'list', 'items', 'elements', 'results',
  'users', 'posts', 'records', 'rows', 'entries', 'values',
  'data', 'children', 'nodes', 'keys',
]);

/**
 * Heuristic: is this likely an array method or a non-DB method?
 * Used to disambiguate .find() / .get() etc.
 *
 * Returns true if the object is known to NOT be a DB handle.
 */
function isLikelyArrayMethod(objectName: string, methodName: string): boolean {
  // If the object is a known non-DB object, skip DB classification
  if (NON_DB_OBJECTS.has(objectName)) return true;

  // Only ambiguous methods — most DB methods (insert, delete, etc.) are never on arrays
  const AMBIGUOUS = new Set(['find', 'findIndex', 'some', 'every', 'get']);
  if (!AMBIGUOUS.has(methodName)) return false;

  return false;
}

/**
 * Get the total count of patterns in the database.
 * Useful for tests to verify minimum coverage.
 */
export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size
    + TRANSFORM_CALCULATE_METHODS.size
    + TRANSFORM_FORMAT_METHODS.size;
}
