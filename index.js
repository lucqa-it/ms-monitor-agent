const { buildServer } = require('./src/api/server');
const config = require('./src/config');

async function start() {
  const server = buildServer();

  try {
    // Escuchar en 0.0.0.0 es crucial para Docker/Kubernetes
    await server.listen({ port: config.PORT, host: config.HOST });
    
    // Banner de inicio profesional
    console.log(`
    ╔════════════════════════════════════════════════════╗
    ║   🚀 Monitor Agent API - System Metrics Service    ║
    ╠════════════════════════════════════════════════════╣
    ║  Status: Online                                    ║
    ║  Port:   ${config.PORT}                            ║
    ║  PID:    ${process.pid}                            ║
    ║  Env:    ${config.ENV}                             ║
    ╚════════════════════════════════════════════════════╝
    `);
    
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }

  // Graceful Shutdown
  // Capturamos señales de terminación para cerrar conexiones limpiamente
  const signals = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
  signals.forEach(signal => {
    process.on(signal, async () => {
      server.log.info(`Signal ${signal} received. Closing server...`);
      await server.close();
      server.log.info('Server closed successfully');
      process.exit(0);
    });
  });
}

start();
