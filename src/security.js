const fs = require('fs');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);
const metrics = require('./metrics');
const axios = require('axios');

/**
 * Realiza una auditoría básica de seguridad del servidor
 * Retorna un puntaje (0-100) y hallazgos.
 */
async function runSecurityAudit() {
  const audit = {
    score: 100,
    findings: [],
    details: {}
  };

  // 1. Verificar SSH Config (PermitRootLogin, PasswordAuthentication)
  // Solo Linux
  if (process.platform === 'linux') {
    try {
      // Intentar leer sshd_config
      const sshConfigPath = '/etc/ssh/sshd_config';
      if (fs.existsSync(sshConfigPath)) {
        const content = fs.readFileSync(sshConfigPath, 'utf8');
        
        // Check PermitRootLogin
        if (/^PermitRootLogin\s+yes/m.test(content)) {
          audit.score -= 20;
          audit.findings.push({ severity: 'high', message: 'SSH Root Login is enabled (PermitRootLogin yes)' });
        }

        // Check PasswordAuthentication (Preferir Keys)
        if (/^PasswordAuthentication\s+yes/m.test(content)) {
          audit.score -= 10;
          audit.findings.push({ severity: 'medium', message: 'SSH Password Authentication is enabled' });
        }
      } else {
        audit.details.ssh = 'Config file not found or not readable';
      }
    } catch (e) {
      audit.details.ssh_error = e.message;
    }
  }

  // 2. Verificar Firewall (UFW) - Solo Linux
  if (process.platform === 'linux') {
    try {
      const { stdout } = await execPromise('sudo ufw status');
      if (stdout.includes('inactive')) {
        audit.score -= 20;
        audit.findings.push({ severity: 'high', message: 'Firewall (UFW) is inactive' });
      } else {
        audit.details.firewall = 'active';
      }
    } catch (e) {
      // Puede que UFW no esté instalado, check iptables o simplemente warn
      audit.findings.push({ severity: 'low', message: 'Could not verify UFW status (requires root or not installed)' });
    }
  }

  // 3. Verificar Usuario de Ejecución
  try {
    const userInfo = require('os').userInfo();
    if (userInfo.username === 'root' || userInfo.uid === 0) {
      audit.score -= 15;
      audit.findings.push({ severity: 'medium', message: 'Agent is running as ROOT (Not recommended for web-facing services)' });
    }
  } catch(e) {}

  // 4. Analizar Puertos Expuestos (Listening)
  try {
    const connections = await metrics.getNetworkConnections();
    const listeningPorts = connections.filter(c => c.state === 'LISTEN');
    
    // Detectar puertos peligrosos comunes expuestos al público (0.0.0.0)
    const dangerousPorts = [21, 23, 3306, 5432, 6379, 27017]; // FTP, Telnet, DBs
    
    listeningPorts.forEach(conn => {
      // Si escucha en todas las interfaces
      if (conn.localAddress === '0.0.0.0' || conn.localAddress === '::') {
         if (dangerousPorts.includes(conn.localPort)) {
            audit.score -= 15;
            audit.findings.push({ severity: 'high', message: `Dangerous port ${conn.localPort} exposed to public (0.0.0.0)` });
         }
      }
    });
    
    audit.details.open_ports = listeningPorts.length;
  } catch (e) {}

  // 5. Verificar Intentos de Fallidos Recientes (Brute Force)
  if (process.platform === 'linux') {
      const sshData = await metrics.getSshActivity();
      if (sshData.status === 'active' && sshData.summary.failed_count > 10) {
          audit.score -= 10;
          audit.findings.push({ severity: 'medium', message: `High number of failed SSH login attempts detected (${sshData.summary.failed_count})` });
      }
  }

  // Normalizar score
  audit.score = Math.max(0, audit.score);
  
  // Categoría
  if (audit.score >= 90) audit.grade = 'A';
  else if (audit.score >= 80) audit.grade = 'B';
  else if (audit.score >= 60) audit.grade = 'C';
  else if (audit.score >= 40) audit.grade = 'D';
  else audit.grade = 'F';

  return audit;
}

/**
 * Obtiene mapa de IPs conectadas con Geolocalización
 * Usa ip-api.com (Gratis, Rate limited 45 req/min)
 */
async function getThreatMap() {
  try {
    const connections = await metrics.getNetworkConnections();
    
    // Filtrar conexiones remotas (excluir localhost y IPs privadas si se desea, 
    // pero a veces queremos ver conexiones internas)
    // Nos interesan las ESTABLISHED entrantes o salientes
    const remoteConns = connections.filter(c => 
      c.state === 'ESTABLISHED' && 
      !c.peerAddress.startsWith('127.') && 
      !c.peerAddress.startsWith('::1') &&
      c.peerAddress !== '0.0.0.0'
    );

    // Extraer IPs únicas para no saturar la API
    const uniqueIps = [...new Set(remoteConns.map(c => c.peerAddress))];
    
    // Limitar a 10 IPs para demo y no ser baneados por rate limit
    const ipsToLocate = uniqueIps.slice(0, 10);
    
    const geoData = [];
    
    // Hacer requests en paralelo (con cuidado)
    // Nota: ip-api no soporta batch en version gratis HTTP, hay que hacer uno por uno o usar endpoint batch POST (pero a veces falla en free)
    // Vamos uno por uno secuencial para ser "polite"
    for (const ip of ipsToLocate) {
      try {
        // Validación básica de IP privada para no enviar a API
        if (isPrivateIP(ip)) {
            geoData.push({ ip, type: 'private', country: 'Local Network', city: '-' });
            continue;
        }

        const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon,isp,query`);
        if (response.data.status === 'success') {
          geoData.push({
            ip: response.data.query,
            type: 'public',
            country: response.data.country,
            city: response.data.city,
            lat: response.data.lat,
            lon: response.data.lon,
            isp: response.data.isp
          });
        }
      } catch (e) {
        // Ignorar errores de geo
      }
    }

    // Unir info de conexión con geo
    const map = remoteConns.map(conn => {
      const geo = geoData.find(g => g.ip === conn.peerAddress) || { country: 'Unknown' };
      return {
        ...conn,
        geo
      };
    });

    return {
      total_connections: remoteConns.length,
      mapped_ips: geoData.length,
      connections: map
    };

  } catch (e) {
    return { error: e.message };
  }
}

function isPrivateIP(ip) {
   // Rangos básicos RFC1918
   return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(ip);
}

module.exports = {
  runSecurityAudit,
  getThreatMap
};
