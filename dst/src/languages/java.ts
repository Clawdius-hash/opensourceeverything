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
  'System.getenv':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },
  'System.getProperty':         { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },

  // -- Properties --
  'Properties.getProperty':     { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },
  'Properties.load':            { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },

  // -- Deserialization --
  'ObjectInputStream.readObject': { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },
  'ObjectMapper.readValue':     { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'ObjectMapper.readTree':      { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'Gson.fromJson':              { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'JAXBContext.createUnmarshaller': { nodeType: 'TRANSFORM', subtype: 'parse',  tainted: false },

  // =========================================================================
  // EGRESS
  // =========================================================================

  // -- Console --
  'System.out.println':         { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.out.print':           { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.out.printf':          { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.err.println':         { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'System.err.print':           { nodeType: 'EGRESS', subtype: 'display',       tainted: false },

  // -- Servlet response --
  'response.getWriter':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.getOutputStream':   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.sendRedirect':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.sendError':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
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
  'ProcessBuilder.start':       { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- JMS / Kafka --
  'JmsTemplate.send':           { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'JmsTemplate.convertAndSend': { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'KafkaTemplate.send':         { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

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
  'PreparedStatement.executeQuery': { nodeType: 'STORAGE', subtype: 'db_read',  tainted: false },
  'PreparedStatement.executeUpdate': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.execute':    { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
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

  // =========================================================================
  // TRANSFORM
  // =========================================================================

  // -- Crypto --
  'MessageDigest.getInstance':    { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'MessageDigest.digest':         { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'Mac.getInstance':              { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'Cipher.getInstance':           { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'SecureRandom.nextBytes':       { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'KeyGenerator.getInstance':     { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'KeyPairGenerator.getInstance': { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },
  'Signature.getInstance':        { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },

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
]);

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    const single = MEMBER_CALLS[calleeChain[0]!];
    if (single) return { ...single };
    return null;
  }

  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };
    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  if (STORAGE_READ_METHODS.has(methodName) && !NON_DB_OBJECTS.has(objectName)) {
    return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
  }
  if (STORAGE_WRITE_METHODS.has(methodName) && !NON_DB_OBJECTS.has(objectName)) {
    return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
  }

  return null;
}

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /Runtime\.(?:getRuntime\(\)\.)?exec\s*\(\s*[^"]/,
  'CWE-89':  /"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*"\s*\+\s*\w+|Statement\.execute(?:Query|Update)?\s*\(\s*[^"]/,
  'CWE-79':  /(?:response\.getWriter\(\)\.(?:print|write)\s*\(\s*request|PrintWriter\.(?:print|write)\s*\(\s*request)/,
  'CWE-502': /ObjectInputStream\s*\(\s*(?:request|socket|input)/,
  'CWE-611': /SAXParserFactory\.newInstance\(\)(?![^\n]*setFeature)/,
  'CWE-798': /(?:apiKey|secret|password|token)\s*=\s*"[^"]{4,}"/,
  'CWE-918': /(?:URL\s*\(\s*request\.getParameter|HttpClient.*URI\.create\s*\(\s*request)/,
};

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /ProcessBuilder\s*\(\s*(?:Arrays\.asList|List\.of)\s*\(/,
  'CWE-89':  /(?:PreparedStatement|JdbcTemplate\.query|createQuery\s*\(\s*"[^"]*:\w+|@Query)/,
  'CWE-79':  /(?:HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml|Jsoup\.clean|ESAPI)/,
  'CWE-502': /(?:ObjectInputFilter|allowedClasses|SerializationUtils)/,
  'CWE-611': /(?:setFeature\s*\(\s*"http:\/\/.*disallow-doctype|XMLConstants\.FEATURE_SECURE_PROCESSING)/,
};

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size;
}
