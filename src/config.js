require('dotenv').config();
const path = require('path');

module.exports = {
  PORT: process.env.PORT || 3456, // Puerto cambiado para evitar conflictos
  HOST: process.env.HOST || '0.0.0.0', // Escuchar en todas las interfaces para contenedores/VMs
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  ENV: process.env.NODE_ENV || 'development'
};
