require('dotenv').config();
const path = require('path');

module.exports = {
  PORT: process.env.PORT || 3456, // Puerto cambiado para evitar conflictos
  HOST: process.env.HOST || '0.0.0.0', // Escuchar en todas las interfaces para contenedores/VMs
  API_KEY: process.env.API_KEY || 'secret-agent-key', // En producción, esto DEBE venir de env
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  ENV: process.env.NODE_ENV || 'development'
};
