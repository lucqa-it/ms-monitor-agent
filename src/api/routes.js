const metrics = require('../metrics');
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

  // --- Nuevos Endpoints de Seguridad y Red ---

  // Obtener conexiones de red activas (Mapeo de red local)
  fastify.get('/network/connections', async (request, reply) => {
    try {
      const connections = await metrics.getNetworkConnections();
      
      // Resumen estadístico
      const summary = {
        total: connections.length,
        listening: connections.filter(c => c.state === 'LISTEN').length,
        established: connections.filter(c => c.state === 'ESTABLISHED').length
      };

      return { 
        summary,
        connections 
      };
    } catch (e) {
      request.log.error(e);
      reply.code(500).send({ error: 'Failed to get network connections' });
    }
  });

  // Obtener actividad SSH (Seguridad)
  fastify.get('/security/ssh', async (request, reply) => {
    try {
      const activity = await metrics.getSshActivity();
      return { activity };
    } catch (e) {
      request.log.error(e);
      reply.code(500).send({ error: 'Failed to analyze SSH logs' });
    }
  });

  // --- Nuevos Endpoints SysAdmin ---

  // Docker Stats (Lista)
  fastify.get('/system/docker', async (request, reply) => {
    const data = await metrics.getDockerStats();
    return { data };
  });

  // Docker Logs
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

  // Docker Inspect (Detalle Completo)
  fastify.get('/system/docker/:id/inspect', async (request, reply) => {
    const { id } = request.params;
    try {
      const data = await metrics.getDockerInspect(id);
      return { data };
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });

  // Users Active
  fastify.get('/system/users', async (request, reply) => {
    const data = await metrics.getUsers();
    return { count: data.length, users: data };
  });

  // Services (Systemd List)
  fastify.get('/system/services', async (request, reply) => {
    const serviceName = request.query.name || '*';
    const data = await metrics.getServices(serviceName);
    return { services: data };
  });

  // Service Logs (Journalctl)
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

  // Service Status Detailed (Systemctl Status)
  fastify.get('/system/services/:name/status', async (request, reply) => {
    const { name } = request.params;
    try {
      const status = await metrics.getServiceStatusDetailed(name);
      return { status };
    } catch (e) {
      reply.code(400).send({ error: e.message });
    }
  });
}

module.exports = routes;
