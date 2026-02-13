const fastify = require('fastify');
const config = require('../config');
const routes = require('./routes');

/**
 * Factoría para crear el servidor API
 */
function buildServer() {
  const isDev = config.ENV === 'development';
  
  const app = fastify({
    logger: {
      level: config.LOG_LEVEL,
      // Solo usar pino-pretty en desarrollo local real
      // En producción (PM2/Docker), usar log JSON estándar (mucho más rápido y seguro)
      transport: isDev ? {
        target: 'pino-pretty',
        options: {
          translateTime: 'HH:MM:ss Z',
          ignore: 'pid,hostname',
        },
      } : undefined,
    },
    // Optimización: Deshabilitar validación de esquema si no se usa intensivamente para ganar microsegundos,
    // pero mantenemos por seguridad por defecto.
  });

  // Registrar rutas
  app.register(routes);

  return app;
}

module.exports = { buildServer };
