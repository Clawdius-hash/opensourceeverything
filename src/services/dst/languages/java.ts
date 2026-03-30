/**
 * Java Callee Pattern Database
 *
 * Maps Java method/class names to DST Neural Map node types.
 * Covers: JDK stdlib, Spring Boot/MVC, JPA/Hibernate, JDBC,
 *         HttpClient, Servlet API, Jackson, SLF4J/Log4j.
 *
 * Sources:
 *   - corpus_audit_java.json (17 Category B + 174 Category A patterns)
 *   - Java/Spring ecosystem knowledge
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

// -- Import all phoneme expansion files -----------------------------------------
import { PHONEMES_JAVA_JDBC_HIBERNATE } from '../phoneme-expansion/java_jdbc_hibernate.js';
import { PHONEMES_JAVA_SERVLET_JSP } from '../phoneme-expansion/java_servlet_jsp.js';
import { PHONEMES_JAVA_SPRING_MVC } from '../phoneme-expansion/java_spring_mvc.js';
import { JAVA_SPRING_ADVANCED_PHONEMES } from '../phoneme-expansion/java_spring_advanced.js';
import { PHONEMES_JAVA_SPRING_SECURITY } from '../phoneme-expansion/java_spring_security.js';
import { PHONEMES_JAVA_COMMONS_CRYPTO } from '../phoneme-expansion/java_commons_crypto.js';
import { PHONEMES_JAVA_DESERIALIZATION } from '../phoneme-expansion/java_deserialization.js';
import { PHONEMES_JAVA_STRUTS_VERTX } from '../phoneme-expansion/java_struts_vertx.js';
import { PHONEMES_JAVA_ANDROID_SDK } from '../phoneme-expansion/java_android_sdk.js';
import { JAKARTA_EE_ENTRIES } from '../phoneme-expansion/java_jakarta_ee.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

const DIRECT_CALLS: Record<string, CalleePattern> = {};

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS
  // =========================================================================

  // -- Servlet request --
  'request.getParameter':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getParameterMap':    { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getParameterValues': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getHeader':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getHeaders':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getCookies':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getInputStream':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getReader':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getRequestURI':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getRequestURL':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getQueryString':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getPathInfo':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getRemoteAddr':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getContentType':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getMethod':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getSession':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getAttribute':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getPart':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getParts':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Alias: req.* (Juliet Servlet pattern) --
  'req.getParameter':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getParameterMap':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getParameterValues':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getHeader':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getHeaders':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getCookies':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getInputStream':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getReader':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getRequestURI':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getRequestURL':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getQueryString':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getPathInfo':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getRemoteAddr':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getAttribute':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.getPart':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Alias: httpRequest.* --
  'httpRequest.getParameter':   { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'httpRequest.getHeader':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'httpRequest.getCookies':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'httpRequest.getQueryString': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'httpRequest.getInputStream': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Alias: servletRequest.* --
  'servletRequest.getParameter':    { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'servletRequest.getHeader':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'servletRequest.getQueryString':  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Spring MVC request binding is annotation-driven but also: --
  'RequestBody':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'RequestParam':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'PathVariable':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'RequestHeader':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'CookieValue':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ModelAttribute':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Console / stdin --
  'System.in':                  { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Scanner.nextLine':           { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Scanner.next':               { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Scanner.nextInt':            { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'BufferedReader.readLine':    { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Console.readLine':           { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Console.readPassword':       { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },

  // -- Network socket (Juliet connect_tcp pattern) --
  // Reading from an outbound TCP socket is attacker-controlled input.
  // Juliet uses: socket.getInputStream(), then wraps in InputStreamReader/BufferedReader.
  'Socket.getInputStream':      { nodeType: 'INGRESS', subtype: 'network_input', tainted: true },
  'socket.getInputStream':      { nodeType: 'INGRESS', subtype: 'network_input', tainted: true },
  'Socket.getOutputStream':     { nodeType: 'EGRESS',  subtype: 'network_output', tainted: false },
  'socket.getOutputStream':     { nodeType: 'EGRESS',  subtype: 'network_output', tainted: false },
  'DatagramSocket.receive':     { nodeType: 'INGRESS', subtype: 'network_input', tainted: true },
  'ServerSocket.accept':        { nodeType: 'INGRESS', subtype: 'network_input', tainted: true },
  // InputStreamReader / DataInputStream wrapping socket reads
  'InputStreamReader.read':     { nodeType: 'INGRESS', subtype: 'network_input', tainted: true },
  'DataInputStream.readUTF':    { nodeType: 'INGRESS', subtype: 'network_input', tainted: true },
  'DataInputStream.readLine':   { nodeType: 'INGRESS', subtype: 'network_input', tainted: true },

  // -- File read --
  'Files.readString':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.readAllLines':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.readAllBytes':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.lines':                { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.newBufferedReader':    { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.list':                 { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.walk':                 { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.exists':               { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Files.size':                 { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'FileInputStream':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // -- Environment --
  // STEP 3: Mark env vars as tainted — attacker-controlled in containerised deployments
  // and in Juliet CWE-78 patterns where env vars feed directly into Runtime.exec().
  'System.getenv':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'System.getProperty':         { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },

  // -- Properties --
  'Properties.getProperty':     { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },
  'Properties.load':            { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },

  // -- Deserialization --
  'ObjectInputStream.readObject': { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },
  'ObjectMapper.readValue':     { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'ObjectMapper.readTree':      { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'Gson.fromJson':              { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'JAXBContext.createUnmarshaller': { nodeType: 'TRANSFORM', subtype: 'parse',  tainted: false },

  // -- JSF (JavaServer Faces) — Jakarta EE --
  'FacesContext.getExternalContext': { nodeType: 'INGRESS', subtype: 'jsf_request', tainted: true },
  'ExternalContext.getRequestParameterMap': { nodeType: 'INGRESS', subtype: 'jsf_request', tainted: true },

  // -- JMS message receive (Jakarta EE) --
  'MessageListener.onMessage':  { nodeType: 'INGRESS', subtype: 'jms_receive',  tainted: true },
  'TextMessage.getText':        { nodeType: 'INGRESS', subtype: 'jms_receive',  tainted: true },
  'JMSConsumer.receive':        { nodeType: 'INGRESS', subtype: 'jms_receive',  tainted: true },

  // =========================================================================
  // EGRESS
  // =========================================================================

  // -- Console --
  'System.out.println':         { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.out.print':           { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.out.printf':          { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.err.println':         { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.err.print':           { nodeType: 'EGRESS', subtype: 'display',       tainted: false },

  // -- PrintWriter (servlet response writer alias) --
  // When `out = response.getWriter()`, calls on `out` must also be classified.
  'out.println':                { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'out.print':                  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'out.write':                  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'out.printf':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'out.flush':                  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'writer.println':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'writer.print':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'writer.write':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'PrintWriter.println':        { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'PrintWriter.print':          { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'PrintWriter.write':          { nodeType: 'EGRESS', subtype: 'display',       tainted: false },

  // -- Servlet response --
  'response.getWriter':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.getOutputStream':   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.sendRedirect':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.sendError':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'HttpServletResponse.sendRedirect': { nodeType: 'EGRESS', subtype: 'redirect', tainted: false },
  'response.setHeader':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.addHeader':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.addCookie':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.setStatus':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.setContentType':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Spring MVC --
  'ResponseEntity.ok':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.notFound':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.badRequest':  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.created':     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.noContent':   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.status':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- File write --
  'Files.write':                { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Files.writeString':          { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Files.copy':                 { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Files.move':                 { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Files.delete':               { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Files.createDirectory':      { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Files.createDirectories':    { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Files.newBufferedWriter':    { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'FileOutputStream':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- Serialization --
  'ObjectMapper.writeValueAsString': { nodeType: 'EGRESS', subtype: 'serialize', tainted: false },
  'ObjectMapper.writeValueAsBytes': { nodeType: 'EGRESS', subtype: 'serialize', tainted: false },
  'Gson.toJson':                { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },

  // -- Email --
  'JavaMailSender.send':        { nodeType: 'EGRESS', subtype: 'email',         tainted: false },
  'Transport.send':             { nodeType: 'EGRESS', subtype: 'email',         tainted: false },

  // -- Logging --
  'logger.info':                { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.debug':               { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.warn':                { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.error':               { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.trace':               { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.info':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.debug':                  { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.warn':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.error':                  { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'LOG.info':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'LOG.debug':                  { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'LOG.warn':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'LOG.error':                  { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'LoggerFactory.getLogger':    { nodeType: 'META',   subtype: 'config',        tainted: false },

  // =========================================================================
  // EXTERNAL
  // =========================================================================

  // -- HttpURLConnection (legacy Java HTTP) --
  'URL.openConnection':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'url.openConnection':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpURLConnection.connect':  { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'connection.connect':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'connection.getInputStream':  { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'connection.getOutputStream': { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'new URL':                    { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'URI.create':                 { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'new URI':                    { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- HttpClient (Java 11+) --
  'HttpClient.send':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.sendAsync':       { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.newHttpClient':   { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.newBuilder':      { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpRequest.newBuilder':     { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- RestTemplate (Spring) --
  'RestTemplate.getForObject':  { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestTemplate.getForEntity':  { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestTemplate.postForObject': { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestTemplate.postForEntity': { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestTemplate.exchange':      { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestTemplate.delete':        { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestTemplate.put':           { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- WebClient (Spring WebFlux) --
  'WebClient.get':              { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'WebClient.post':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'WebClient.put':              { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'WebClient.delete':           { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'WebClient.patch':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'WebClient.create':           { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- OkHttp --
  'OkHttpClient.newCall':       { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- Process --
  'Runtime.exec':               { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Runtime.getRuntime.exec':    { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'runtime.exec':               { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'ProcessBuilder.start':       { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- EJB / JNDI (Jakarta EE) --
  'EJBContext.lookup':          { nodeType: 'EXTERNAL', subtype: 'jndi_lookup',    tainted: true },
  'SessionContext.getBusinessObject': { nodeType: 'EXTERNAL', subtype: 'ejb_remote', tainted: false },

  // -- JMS / Kafka --
  'JmsTemplate.send':           { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'JmsTemplate.convertAndSend': { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'KafkaTemplate.send':         { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // -- JMS send (Jakarta EE 2.0+ API) --
  'JMSProducer.send':           { nodeType: 'EGRESS', subtype: 'jms_send',      tainted: false },

  // =========================================================================
  // STORAGE
  // =========================================================================

  // -- JDBC --
  'DriverManager.getConnection':  { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },
  'DataSource.getConnection':     { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },
  'Connection.prepareStatement':  { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'Connection.createStatement':   { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'Connection.commit':            { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'Connection.rollback':          { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'Connection.close':             { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },
  'Statement.executeQuery':       { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'Statement.executeUpdate':      { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'Statement.execute':            { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'Statement.addBatch':           { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'Statement.executeBatch':       { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'Statement.clearBatch':         { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'PreparedStatement.executeQuery': { nodeType: 'STORAGE', subtype: 'db_read',  tainted: false },
  'PreparedStatement.executeUpdate': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.execute':    { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'PreparedStatement.addBatch':   { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'PreparedStatement.executeBatch': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setString':  { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'PreparedStatement.setInt':     { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'ResultSet.getString':          { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'ResultSet.getInt':             { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'ResultSet.getLong':            { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'ResultSet.next':               { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },

  // -- JPA / Hibernate --
  'EntityManager.find':           { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'EntityManager.persist':        { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'EntityManager.merge':          { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'EntityManager.remove':         { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'EntityManager.flush':          { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'EntityManager.createQuery':    { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'EntityManager.createNativeQuery': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'EntityManager.getTransaction': { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },

  // -- Spring Data JPA --
  'repository.findAll':           { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'repository.findById':          { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'repository.findBy':            { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'repository.save':              { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'repository.saveAll':           { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'repository.saveAndFlush':      { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'repository.delete':            { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'repository.deleteById':        { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'repository.deleteAll':         { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'repository.count':             { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'repository.existsById':        { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },

  // -- JdbcTemplate (Spring) --
  'JdbcTemplate.query':           { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'JdbcTemplate.queryForObject':  { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'JdbcTemplate.queryForList':    { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'JdbcTemplate.update':          { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'JdbcTemplate.execute':         { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'JdbcTemplate.batchUpdate':     { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'NamedParameterJdbcTemplate.query': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'NamedParameterJdbcTemplate.update': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // -- Redis (Spring) --
  'RedisTemplate.opsForValue':    { nodeType: 'STORAGE', subtype: 'cache_read', tainted: false },
  'StringRedisTemplate.opsForValue': { nodeType: 'STORAGE', subtype: 'cache_read', tainted: false },

  // -- HTTP Session (CWE-384/501: Session Fixation / Trust Boundary Violation) --
  'HttpSession.setAttribute':     { nodeType: 'STORAGE', subtype: 'session_write', tainted: false },
  'HttpSession.getAttribute':     { nodeType: 'STORAGE', subtype: 'session_read',  tainted: false },
  'session.setAttribute':         { nodeType: 'STORAGE', subtype: 'session_write', tainted: false },
  'session.getAttribute':         { nodeType: 'STORAGE', subtype: 'session_read',  tainted: false },

  // -- LDAP (CWE-90: LDAP Injection) --
  // Juliet CWE-90 uses DirContext.search(name, filter, controls) where filter is user-controlled.
  'DirContext.search':            { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'InitialDirContext.search':     { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'LdapContext.search':           { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'InitialLdapContext.search':    { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'dirContext.search':            { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'ldapContext.search':           { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'DirContext.bind':              { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'InitialDirContext.bind':       { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },
  'DirContext.lookup':            { nodeType: 'STORAGE', subtype: 'ldap_query',  tainted: false },

  // -- XPath (CWE-643: XPath Injection) --
  // Juliet CWE-643 uses XPath.evaluate(expression, context) where expression is user-controlled.
  'XPath.evaluate':               { nodeType: 'STORAGE', subtype: 'xpath_query', tainted: false },
  'xpath.evaluate':               { nodeType: 'STORAGE', subtype: 'xpath_query', tainted: false },
  'XPathExpression.evaluate':     { nodeType: 'STORAGE', subtype: 'xpath_query', tainted: false },
  'xpathExpression.evaluate':     { nodeType: 'STORAGE', subtype: 'xpath_query', tainted: false },

  // -- File access (CWE-22 path traversal sinks) --
  'File.new':                     { nodeType: 'STORAGE', subtype: 'file_access', tainted: false },
  'FileInputStream.new':          { nodeType: 'STORAGE', subtype: 'file_read',   tainted: false },
  'FileOutputStream.new':         { nodeType: 'STORAGE', subtype: 'file_write',  tainted: false },
  'FileReader.new':               { nodeType: 'STORAGE', subtype: 'file_read',   tainted: false },

  // =========================================================================
  // TRANSFORM
  // =========================================================================

  // -- Path resolution --
  'Paths.get':                    { nodeType: 'TRANSFORM', subtype: 'path_resolve', tainted: false },

  // -- Crypto --
  'MessageDigest.getInstance':    { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'MessageDigest.digest':         { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'Mac.getInstance':              { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'Cipher.getInstance':           { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'SecureRandom.nextBytes':       { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'KeyGenerator.getInstance':     { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'KeyPairGenerator.getInstance': { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'Signature.getInstance':        { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'SecretKeySpec.new':            { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },

  // -- Weak PRNG (CWE-338) — Math.random and java.util.Random are cryptographically weak --
  'Math.random':                  { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },
  'Random.nextInt':               { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },
  'Random.nextDouble':            { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },
  'Random.nextLong':              { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },
  'Random.nextFloat':             { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },
  'Random.nextBoolean':           { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },
  'Random.nextBytes':             { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },
  'Random.nextGaussian':          { nodeType: 'TRANSFORM', subtype: 'prng_weak', tainted: false },

  // -- Encoding --
  'Base64.getEncoder':            { nodeType: 'TRANSFORM', subtype: 'encode',   tainted: false },
  'Base64.getDecoder':            { nodeType: 'TRANSFORM', subtype: 'encode',   tainted: false },
  'URLEncoder.encode':            { nodeType: 'TRANSFORM', subtype: 'encode',   tainted: false },
  'URLDecoder.decode':            { nodeType: 'TRANSFORM', subtype: 'encode',   tainted: false },
  'StandardCharsets.UTF_8':       { nodeType: 'TRANSFORM', subtype: 'encode',   tainted: false },

  // -- Type conversion --
  'Integer.parseInt':             { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'Integer.valueOf':              { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'Long.parseLong':               { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'Double.parseDouble':           { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'Boolean.parseBoolean':         { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'String.valueOf':               { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'String.format':                { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'UUID.randomUUID':              { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'UUID.fromString':              { nodeType: 'TRANSFORM', subtype: 'parse',    tainted: false },

  // -- Date / time --
  'LocalDateTime.now':            { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'LocalDate.now':                { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'Instant.now':                  { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'ZonedDateTime.now':            { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'DateTimeFormatter.ofPattern':  { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'SimpleDateFormat.parse':       { nodeType: 'TRANSFORM', subtype: 'parse',    tainted: false },
  'SimpleDateFormat.format':      { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },

  // -- Regex --
  'Pattern.compile':              { nodeType: 'TRANSFORM', subtype: 'parse',    tainted: false },
  'Pattern.matches':              { nodeType: 'TRANSFORM', subtype: 'parse',    tainted: false },

  // -- URL --
  'URI.create':                   { nodeType: 'TRANSFORM', subtype: 'parse',    tainted: false },

  // -- XML sanitization --
  'HtmlUtils.htmlEscape':         { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },
  'StringEscapeUtils.escapeHtml4':{ nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },
  'Jsoup.clean':                  { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },
  'ESAPI.encoder':                { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },

  // =========================================================================
  // CONTROL
  // =========================================================================

  // -- Concurrency --
  'Thread.start':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Thread.sleep':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Thread.join':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ExecutorService.submit':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ExecutorService.execute':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ExecutorService.invokeAll':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ExecutorService.shutdown':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CompletableFuture.supplyAsync':{ nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CompletableFuture.runAsync':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CompletableFuture.allOf':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CompletableFuture.anyOf':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CountDownLatch.await':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CountDownLatch.countDown':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Semaphore.acquire':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Semaphore.release':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ReentrantLock.lock':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ReentrantLock.unlock':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ScheduledExecutorService.schedule': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ScheduledExecutorService.scheduleAtFixedRate': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Validation (Spring/Bean Validation) --
  'Validator.validate':           { nodeType: 'CONTROL', subtype: 'validation', tainted: false },

  // -- Exit --
  'System.exit':                  { nodeType: 'CONTROL', subtype: 'guard',      tainted: false },

  // =========================================================================
  // AUTH
  // =========================================================================

  // -- Spring Security --
  'SecurityContextHolder.getContext': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'Authentication.getPrincipal':  { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'UserDetailsService.loadUserByUsername': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'BCryptPasswordEncoder.encode': { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'BCryptPasswordEncoder.matches':{ nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'PasswordEncoder.encode':       { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'PasswordEncoder.matches':      { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'AuthenticationManager.authenticate': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },

  // -- JWT (jjwt) --
  'Jwts.builder':                 { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'Jwts.parserBuilder':           { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'Jwts.parser':                  { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },

  // =========================================================================
  // STRUCTURAL
  // =========================================================================

  // -- Spring Bean DI --
  'ApplicationContext.getBean':   { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },

  // -- CDI (Jakarta EE) --
  'Instance.select':            { nodeType: 'STRUCTURAL', subtype: 'cdi_injection', tainted: false },
  'BeanManager.getReference':   { nodeType: 'STRUCTURAL', subtype: 'cdi_injection', tainted: false },

  // -- Spring routing annotations (mapped) --
  'RequestMapping':               { nodeType: 'STRUCTURAL', subtype: 'route',   tainted: false },
  'GetMapping':                   { nodeType: 'STRUCTURAL', subtype: 'route',   tainted: false },
  'PostMapping':                  { nodeType: 'STRUCTURAL', subtype: 'route',   tainted: false },
  'PutMapping':                   { nodeType: 'STRUCTURAL', subtype: 'route',   tainted: false },
  'DeleteMapping':                { nodeType: 'STRUCTURAL', subtype: 'route',   tainted: false },
  'PatchMapping':                 { nodeType: 'STRUCTURAL', subtype: 'route',   tainted: false },

  // =========================================================================
  // META
  // =========================================================================

  'Environment.getActiveProfiles': { nodeType: 'META', subtype: 'config',      tainted: false },
  'SpringApplication.run':        { nodeType: 'META', subtype: 'config',       tainted: false },
};

// =========================================================================
// MERGED PHONEME DICTIONARY — all expansion entries in one lookup table
// =========================================================================
// The phoneme expansion agents wrote standalone files but never wired them
// into the lookup path. This merged dictionary combines ALL expansion entries
// so lookupCallee() can find them.

const EXPANSION_ENTRIES: Record<string, CalleePattern> = {
  ...PHONEMES_JAVA_JDBC_HIBERNATE,
  ...PHONEMES_JAVA_SERVLET_JSP,
  ...PHONEMES_JAVA_SPRING_MVC,
  ...JAVA_SPRING_ADVANCED_PHONEMES,
  ...PHONEMES_JAVA_SPRING_SECURITY,
  ...PHONEMES_JAVA_COMMONS_CRYPTO,
  ...PHONEMES_JAVA_DESERIALIZATION,
  ...PHONEMES_JAVA_STRUTS_VERTX,
  ...PHONEMES_JAVA_ANDROID_SDK,
  ...JAKARTA_EE_ENTRIES,
};

// -- Wildcard --
const STORAGE_READ_METHODS = new Set([
  'findAll', 'findById', 'findOne', 'findBy', 'find',
  'getOne', 'getReferenceById', 'getById',
  'query', 'queryForObject', 'queryForList',
  'executeQuery', 'count', 'exists', 'existsById',
]);

const STORAGE_WRITE_METHODS = new Set([
  'save', 'saveAll', 'saveAndFlush', 'persist', 'merge',
  'delete', 'deleteById', 'deleteAll', 'remove', 'flush',
  'update', 'execute', 'executeUpdate',
  'batchUpdate', 'insert',
]);

const NON_DB_OBJECTS = new Set([
  'request', 'response', 'System', 'this',
  'logger', 'log', 'LOG', 'Files', 'File', 'Path',
  'ObjectMapper', 'Gson', 'HttpClient', 'RestTemplate', 'WebClient',
  'String', 'Integer', 'Long', 'Double', 'Boolean',
  'list', 'map', 'set', 'array', 'data', 'items', 'result',
  'Thread', 'CompletableFuture', 'ExecutorService',
  'FacesContext', 'ExternalContext', 'MessageListener', 'TextMessage',
  'JMSConsumer', 'JMSProducer', 'Instance', 'BeanManager',
  'EJBContext', 'SessionContext',
]);

// =========================================================================
// Variable-to-class name resolution
// =========================================================================
// In Java, variables are lowercase (connection, statement, cipher, md)
// but the phoneme dictionary uses PascalCase class names (Connection,
// Statement, Cipher, MessageDigest). This map resolves common variable
// names to their class names so lookupCallee can match them.

const VARIABLE_TO_CLASS: Record<string, string> = {
  // JDBC
  'connection': 'Connection', 'conn': 'Connection', 'con': 'Connection', 'dbConnection': 'Connection', 'dbConn': 'Connection', 'sqlConnection': 'Connection',
  'statement': 'Statement', 'stmt': 'Statement', 'sqlStatement': 'Statement', 'st': 'Statement',
  'preparedStatement': 'PreparedStatement', 'pstmt': 'PreparedStatement', 'ps': 'PreparedStatement',
  'callableStatement': 'CallableStatement', 'cs': 'CallableStatement', 'cstmt': 'CallableStatement',
  'resultSet': 'ResultSet', 'rs': 'ResultSet', 'rset': 'ResultSet',
  // Crypto
  'cipher': 'Cipher', 'c': 'Cipher',
  'messageDigest': 'MessageDigest', 'md': 'MessageDigest', 'digest': 'MessageDigest',
  'mac': 'Mac',
  'signature': 'Signature', 'sig': 'Signature',
  'secureRandom': 'SecureRandom', 'random': 'SecureRandom', 'sr': 'SecureRandom',
  'keyGenerator': 'KeyGenerator', 'keyGen': 'KeyGenerator', 'kg': 'KeyGenerator',
  'keyPairGenerator': 'KeyPairGenerator', 'kpg': 'KeyPairGenerator',
  // Hibernate
  'session': 'Session', 'hibernateSession': 'Session',
  'sessionFactory': 'SessionFactory',
  'entityManager': 'EntityManager', 'em': 'EntityManager',
  'criteriaBuilder': 'CriteriaBuilder', 'cb': 'CriteriaBuilder',
  // Spring
  'restTemplate': 'RestTemplate',
  'webClient': 'WebClient',
  'jdbcTemplate': 'JdbcTemplate',
  'namedParameterJdbcTemplate': 'NamedParameterJdbcTemplate',
  'kafkaTemplate': 'KafkaTemplate',
  'jmsTemplate': 'JmsTemplate',
  'redisTemplate': 'RedisTemplate',
  // JNDI / LDAP
  'initialContext': 'InitialContext', 'ctx': 'InitialContext',
  'directoryContext': 'DirContext', 'dirContext': 'DirContext', 'dirCtx': 'DirContext',
  'ldapContext': 'LdapContext', 'ldapCtx': 'LdapContext',
  'initialDirContext': 'InitialDirContext',
  // Process
  'runtime': 'Runtime',
  'processBuilder': 'ProcessBuilder', 'pb': 'ProcessBuilder',
  // IO — include Juliet naming patterns like readerBuffered, readerInputStream
  'scanner': 'Scanner',
  'bufferedReader': 'BufferedReader', 'br': 'BufferedReader', 'reader': 'BufferedReader',
  'readerBuffered': 'BufferedReader',
  'readerInputStream': 'InputStreamReader',
  'inputStreamReader': 'InputStreamReader',
  'isr': 'InputStreamReader',
  'dataInputStream': 'DataInputStream', 'dis': 'DataInputStream',
  'dataOutputStream': 'DataOutputStream', 'dos': 'DataOutputStream',
  // Network
  'socket': 'Socket', 'serverSocket': 'ServerSocket',
  'datagramSocket': 'DatagramSocket',
  // HttpClient
  'httpClient': 'HttpClient', 'client': 'HttpClient',
  // ORM
  'sqlSession': 'SqlSession',
  // Deserialization
  'objectInputStream': 'ObjectInputStream', 'ois': 'ObjectInputStream',
  'objectMapper': 'ObjectMapper', 'mapper': 'ObjectMapper',
  // DataSource / pools
  'dataSource': 'DataSource', 'ds': 'DataSource',
  'hikariDataSource': 'HikariDataSource',
};

// Helper: try to resolve a key across MEMBER_CALLS + EXPANSION_ENTRIES
function lookupInAllDicts(key: string): CalleePattern | undefined {
  return MEMBER_CALLS[key] ?? EXPANSION_ENTRIES[key];
}

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    const single = lookupInAllDicts(calleeChain[0]!);
    if (single) return { ...single };
    return null;
  }

  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  // Try exact match in both dictionaries
  const member = lookupInAllDicts(exactKey);
  if (member) return { ...member };

  // Variable-to-class resolution: try PascalCase class name
  // e.g., connection.prepareCall -> Connection.prepareCall
  const className = VARIABLE_TO_CLASS[objectName];
  if (className) {
    const classKey = `${className}.${methodName}`;
    const classMatch = lookupInAllDicts(classKey);
    if (classMatch) return { ...classMatch };
  }

  // Auto-PascalCase: if objectName starts lowercase, try uppercasing first char
  // This catches patterns like cipher.doFinal -> Cipher.doFinal
  if (objectName.length > 0 && objectName[0] === objectName[0].toLowerCase() && objectName[0] !== objectName[0].toUpperCase()) {
    const pascalName = objectName[0].toUpperCase() + objectName.slice(1);
    const pascalKey = `${pascalName}.${methodName}`;
    const pascalMatch = lookupInAllDicts(pascalKey);
    if (pascalMatch) return { ...pascalMatch };
  }

  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = lookupInAllDicts(fullPath);
    if (fullMember) return { ...fullMember };
    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = lookupInAllDicts(lastTwo);
    if (deepMember) return { ...deepMember };

    // Also try variable-to-class on the second-to-last element
    const secondToLast = calleeChain[calleeChain.length - 2]!;
    const secondClassName = VARIABLE_TO_CLASS[secondToLast];
    if (secondClassName) {
      const deepClassKey = `${secondClassName}.${methodName}`;
      const deepClassMatch = lookupInAllDicts(deepClassKey);
      if (deepClassMatch) return { ...deepClassMatch };
    }
    // Auto-PascalCase on second-to-last
    if (secondToLast.length > 0 && secondToLast[0] === secondToLast[0].toLowerCase() && secondToLast[0] !== secondToLast[0].toUpperCase()) {
      const pascal2 = secondToLast[0].toUpperCase() + secondToLast.slice(1);
      const pascal2Key = `${pascal2}.${methodName}`;
      const pascal2Match = lookupInAllDicts(pascal2Key);
      if (pascal2Match) return { ...pascal2Match };
    }
  }

  // Wildcard: known storage methods on unknown objects
  if (STORAGE_READ_METHODS.has(methodName) && !NON_DB_OBJECTS.has(objectName)) {
    return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
  }
  if (STORAGE_WRITE_METHODS.has(methodName) && !NON_DB_OBJECTS.has(objectName)) {
    return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
  }

  // Method-name-only fallback for dangerous methods on any receiver
  // This catches patterns like: someObj.executeQuery(sql) where someObj
  // is a local variable that we can't resolve to a class name
  const DANGEROUS_METHOD_PATTERNS: Record<string, CalleePattern> = {
    'executeQuery':  { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
    'executeUpdate': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
    'execute':       { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
    'addBatch':      { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
    'executeBatch':  { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
    'prepareCall':   { nodeType: 'STORAGE', subtype: 'db_stored_proc', tainted: false },
    'prepareStatement': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
    'createStatement': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
    'exec':          { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
    'lookup':        { nodeType: 'EXTERNAL', subtype: 'jndi_lookup', tainted: true },
  };
  if (!NON_DB_OBJECTS.has(objectName)) {
    const dangerousMatch = DANGEROUS_METHOD_PATTERNS[methodName];
    if (dangerousMatch) return { ...dangerousMatch };
  }

  return null;
}

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /Runtime\.(?:getRuntime\(\)\.)?exec\s*\(\s*[^"]/,
  'CWE-89':  /"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*"\s*\+\s*\w+|(?:Statement|statement|stmt)\.execute(?:Query|Update)?\s*\(\s*[^")]/,
  'CWE-79':  /(?:response\.getWriter\(\)\.(?:print|write)\s*\(\s*(?:request|param|input|query|user|data|name|value)|PrintWriter\.(?:print|write)\s*\(\s*(?:request|param|input))/,
  'CWE-22':  /new\s+(?:java\.io\.)?File\s*\([^)]*(?:param|input|request|user|path|fileName|filePath|name)|new\s+(?:java\.io\.)?FileInputStream\s*\([^)]*(?:param|input|request|user|path|fileName|name)/,
  'CWE-90':  /(?:search|lookup)\s*\(\s*[^"]*(?:param|input|request|user|query|filter|dn|name)|(?:DirContext|LdapContext|InitialDirContext).*search\s*\(/,
  'CWE-327': /Cipher\.getInstance\s*\(\s*"(?:DES|RC2|RC4|Blowfish|DESede|AES\/ECB)|MessageDigest\.getInstance\s*\(\s*"(?:MD5|MD2|SHA-1|SHA1)"/,
  'CWE-328': /MessageDigest\.getInstance\s*\(\s*"(?:MD5|MD2|MD4|SHA-1|SHA1)"/,
  'CWE-501': /(?:request\.getSession\(\)|session)\.setAttribute\s*\([^)]*(?:param|input|request\.get|user)/,
  'CWE-502': /ObjectInputStream\s*\(\s*(?:request|socket|input)/,
  'CWE-611': /SAXParserFactory\.newInstance\(\)(?![^\n]*setFeature)/,
  'CWE-798': /(?:apiKey|secret|password|token)\s*=\s*"[^"]{4,}"/,
  'CWE-918': /(?:URL\s*\(\s*request\.getParameter|HttpClient.*URI\.create\s*\(\s*request)/,
};

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /ProcessBuilder\s*\(\s*(?:Arrays\.asList|List\.of)\s*\(/,
  'CWE-89':  /(?:PreparedStatement|preparedStatement|pstmt|JdbcTemplate\.query|createQuery\s*\(\s*"[^"]*:\w+|@Query|setString|setInt|setLong)/,
  'CWE-79':  /(?:HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml|Jsoup\.clean|ESAPI|encodeForHTML)/,
  'CWE-22':  /(?:FilenameUtils\.getName|Paths\.get\s*\([^)]*\)\.normalize|\.getCanonicalPath|SecurityManager|TESTFILES_DIR)/,
  'CWE-90':  /(?:escapeLDAPSearchFilter|LdapEncoder\.filterEncode|FilterEncoder)/,
  'CWE-327': /Cipher\.getInstance\s*\(\s*"(?:AES\/(?:GCM|CBC|CTR)|RSA\/ECB\/OAEPWith|ChaCha20)"/,
  'CWE-328': /MessageDigest\.getInstance\s*\(\s*"(?:SHA-256|SHA-384|SHA-512|SHA3-)"/,
  'CWE-501': /(?:session\.invalidate|request\.getSession\(false\))/,
  'CWE-502': /(?:ObjectInputFilter|allowedClasses|SerializationUtils)/,
  'CWE-611': /(?:setFeature\s*\(\s*"http:\/\/.*disallow-doctype|XMLConstants\.FEATURE_SECURE_PROCESSING)/,
};

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + Object.keys(EXPANSION_ENTRIES).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size;
}
