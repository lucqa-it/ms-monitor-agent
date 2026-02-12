const metrics = require('../metrics');
const security = require('../security');
const filesystem = require('../filesystem');
const config = require('../config');

/**
 * Definición de rutas del API
 * @param {import('fastify').FastifyInstance} fastify 
 */
async function routes(fastify, options) {
  
  // Middleware de autenticación
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url === '/health' || request.routerPath === '/health') return;

    const authHeader = request.headers['x-api-key'];
    if (!authHeader || authHeader !== config.API_KEY) {
      reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing API Key' });
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

  // --- Nuevos Endpoints Filesystem ---

  // Buscar archivos grandes
  // GET /system/files/large?path=/var/log&min=50M&limit=5
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

  // Eliminar archivo (PELIGROSO)
  // DELETE /system/files
  // Body: { "path": "/var/log/old_log.gz" }
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
