const NodeRSA = require('node-rsa');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // Usar módulo nativo

const KEYS_DIR = path.join(__dirname, '..', 'secure');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const SECRET_FILE_PATH = path.join(KEYS_DIR, '.secret');

// Asegurar directorio
if (!fs.existsSync(KEYS_DIR)) {
  fs.mkdirSync(KEYS_DIR, { mode: 0o700 }); // Solo root/owner
}

let keyPair = null;
let agentSecret = null;
let sessionToken = null; // Token rotativo de sesión (en memoria)

/**
 * Inicializa el sistema criptográfico del agente
 * Genera claves RSA si no existen y rota el API Secret si es necesario
 */
function initCrypto() {
  // 1. Cargar o Generar API Secret (Master Key persistente)
  if (fs.existsSync(SECRET_FILE_PATH)) {
    agentSecret = fs.readFileSync(SECRET_FILE_PATH, 'utf8').trim();
  } else {
    agentSecret = crypto.randomUUID(); // Usar crypto.randomUUID() nativo
    fs.writeFileSync(SECRET_FILE_PATH, agentSecret, { mode: 0o600 });
    console.log('\n==================================================');
    console.log('🔐 NUEVO AGENTE INICIALIZADO');
    console.log('🔑 API KEY MAESTRA (Guardar en lugar seguro):');
    console.log(`   ${agentSecret}`);
    console.log('==================================================\n');
  }

  // 2. Generar Session Token (Rotativo, solo en memoria)
  sessionToken = crypto.randomUUID();
  console.log('🎟️  SESSION TOKEN GENERADO (Válido hasta reinicio):');
  console.log(`   ${sessionToken}`);
  console.log('--------------------------------------------------');

  // 3. Cargar o Generar RSA Keys (2048 bits)
  if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    const privateKeyData = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    keyPair = new NodeRSA(privateKeyData);
  } else {
    console.log('⚙️ Generando claves de cifrado RSA-2048 (esto puede tardar un momento)...');
    keyPair = new NodeRSA({ b: 2048 });
    
    const publicPem = keyPair.exportKey('public');
    const privatePem = keyPair.exportKey('private');

    fs.writeFileSync(PUBLIC_KEY_PATH, publicPem, { mode: 0o644 });
    fs.writeFileSync(PRIVATE_KEY_PATH, privatePem, { mode: 0o600 });
    console.log('✅ Claves criptográficas generadas.');
  }
}

/**
 * Desencripta datos enviados por el cliente (cifrados con nuestra clave pública)
 */
function decrypt(encryptedData) {
  if (!keyPair) throw new Error('Crypto not initialized');
  try {
    return keyPair.decrypt(encryptedData, 'utf8');
  } catch (e) {
    throw new Error('Decryption failed');
  }
}

/**
 * Retorna la clave pública para que el cliente cifre sus mensajes
 */
function getPublicKey() {
  if (!keyPair) initCrypto();
  return keyPair.exportKey('public');
}

/**
 * Valida si el token proporcionado es válido (Master Key o Session Token)
 */
function validateToken(token) {
  return token === agentSecret || token === sessionToken;
}

module.exports = {
  initCrypto,
  getPublicKey,
  decrypt,
  validateToken,
  getAgentSecret: () => agentSecret,
  getSessionToken: () => sessionToken
};
