const metrics = require('../metrics');
const security = require('../security');
const filesystem = require('../filesystem');
const config = require('../config');
const cryptoManager = require('../crypto');

// Inicializar criptografía al cargar rutas
cryptoManager.initCrypto();

/**
 * Definición de rutas del API
 * @param {import('fastify').FastifyInstance} fastify 
 */
async function routes(fastify, options) {
  
  // --- Endpoint Público para Handshake (Intercambio de claves) ---
  // El cliente llama aquí para obtener la Public Key del agente y poder enviarle credenciales cifradas
  fastify.get('/auth/handshake', async (request, reply) => {
    return { 
      publicKey: cryptoManager.getPublicKey(),
      algorithm: 'RSA-2048',
      format: 'PKCS#8'
    };
  });

  // --- Middleware de Autenticación Mejorado ---
  fastify.addHook('preHandler', async (request, reply) => {
    // Excepciones públicas (Health y Handshake)
    // Se usa request.url.startsWith para mayor robustez frente a query params o trailing slashes
    if (request.routerPath === '/health' || 
        request.routerPath === '/auth/handshake' || 
        request.url.startsWith('/auth/handshake')) {
      return;
    }

    const authHeader = request.headers['x-api-key'];
    const authEncrypted = request.headers['x-auth-secure']; // Nuevo header cifrado

    let token = null;

    // Método 1: Header Estándar (Legacy/Inseguro si no es HTTPS)
    if (authHeader) {
        token = authHeader;
    } 
    // Método 2: Header Cifrado (Seguro incluso en HTTP)
    // El cliente cifra el API Key con la clave pública del agente
    else if (authEncrypted) {
        try {
            token = cryptoManager.decrypt(authEncrypted);
        } catch (e) {
            reply.code(401).send({ error: 'Secure handshake failed', message: 'Invalid encrypted token' });
            return reply;
        }
    }

    // Validar Token
    // Nota: Solo aceptamos el token seguro generado por el sistema criptográfico
    // Se elimina el fallback a config.API_KEY para máxima seguridad
    // Aceptamos Master Key (agentSecret) O Session Token (sessionToken)
    if (!token || !cryptoManager.validateToken(token)) {
      reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing API credentials' });
      return reply;
    }
  });

  // --- Endpoints Básicos ---

  fastify.get('/health', async (request, reply) => {
    return { status: 'ok', uptime: process.uptime() };
  });

  fastify.get('/system', async (request, reply) => {
    const data = await metrics.getStaticData();
    return { data };
  });

  fastify.get('/metrics', async (request, reply) => {
    const data = await metrics.getDynamicData();
    if (!data) {
      reply.code(500).send({ error: 'Internal Server Error', message: 'Failed to collect metrics' });
      return;
    }
    return { data };
  });

  // --- Endpoints de Seguridad y Red ---

  fastify.get('/network/connections', async (request, reply) => {
    try {
      const connections = await metrics.getNetworkConnections();
      const summary = {
        total: connections.length,
        listening: connections.filter(c => c.state === 'LISTEN').length,
        established: connections.filter(c => c.state === 'ESTABLISHED').length
      };
      return { summary, connections };
    } catch (e) {
      request.log.error(e);
      reply.code(500).send({ error: 'Failed to get network connections' });
    }
  });

  fastify.get('/security/ssh', async (request, reply) => {
    try {
      const activity = await metrics.getSshActivity();
      return { activity };
    } catch (e) {
      request.log.error(e);
      reply.code(500).send({ error: 'Failed to analyze SSH logs' });
    }
  });

  fastify.get('/security/audit', async (request, reply) => {
    try {
      const audit = await security.runSecurityAudit();
      return { audit };
    } catch (e) {
      request.log.error(e);
      reply.code(500).send({ error: 'Security audit failed', details: e.message });
    }
  });

  fastify.get('/network/map', async (request, reply) => {
    try {
      const map = await security.getThreatMap();
      return { map };
    } catch (e) {
      request.log.error(e);
      reply.code(500).send({ error: 'Threat map generation failed', details: e.message });
    }
  });

  // --- Endpoints SysAdmin ---

  fastify.get('/system/docker', async (request, reply) => {
    const data = await metrics.getDockerStats();
    return { data };
  });

  fastify.get('/system/docker/:id/logs', async (request, reply) => {
    const { id } = request.params;
    const { lines } = request.query;
    try {
      const logs = await metrics.getDockerLogs(id, lines);
      return { logs };
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  fastify.get('/system/docker/:id/inspect', async (request, reply) => {
    const { id } = request.params;
    try {
      const data = await metrics.getDockerInspect(id);
      return { data };
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  fastify.get('/system/users', async (request, reply) => {
    const data = await metrics.getUsers();
    return { count: data.length, users: data };
  });

  fastify.get('/system/services', async (request, reply) => {
    const serviceName = request.query.name || '*';
    const data = await metrics.getServices(serviceName);
    return { services: data };
  });

  fastify.get('/system/services/:name/logs', async (request, reply) => {
    const { name } = request.params;
    const { lines } = request.query;
    try {
      const logs = await metrics.getServiceLogs(name, lines);
      return { logs };
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  fastify.get('/system/services/:name/status', async (request, reply) => {
    const { name } = request.params;
    try {
      const status = await metrics.getServiceStatusDetailed(name);
      return { status };
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  // --- Endpoints Filesystem ---

  fastify.get('/system/fs/list', async (request, reply) => {
    const targetPath = request.query.path || (process.platform === 'win32' ? process.cwd() : '/var/log');
    const limit = request.query.limit;
    const offset = request.query.offset;
    try {
      const result = await filesystem.listDirectory(targetPath, { limit, offset });
      return result;
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  fastify.get('/system/fs/stat', async (request, reply) => {
    const targetPath = request.query.path;
    try {
      const result = await filesystem.statPath(targetPath);
      return result;
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  fastify.get('/system/fs/read', async (request, reply) => {
    const targetPath = request.query.path;
    const offset = request.query.offset;
    const tailBytes = request.query.tailBytes;
    const maxBytes = request.query.maxBytes;
    const encoding = request.query.encoding;
    try {
      const result = await filesystem.readFileChunk(targetPath, { offset, tailBytes, maxBytes, encoding });
      return result;
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  fastify.get('/system/files/large', async (request, reply) => {
    const dirPath = request.query.path || '/var';
    const minSize = request.query.min || '100M';
    const limit = parseInt(request.query.limit) || 10;
    
    try {
      const files = await filesystem.findLargeFiles(dirPath, minSize, limit);
      return { files };
    } catch (e) {
      reply.code(500).send({ error: e.message });
    }
  });

  fastify.delete('/system/files', async (request, reply) => {
    const { path } = request.body || {};
    if (!path) {
      reply.code(400).send({ error: 'Path is required in body' });
      return;
    }
    
    try {
      const result = await filesystem.deleteFile(path);
      return result;
    } catch (e) {
      request.log.warn(`File deletion failed: ${path} - ${e.message}`);
      reply.code(403).send({ error: e.message });
    }
  });
}

module.exports = routes;
