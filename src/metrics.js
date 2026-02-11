const si = require('systeminformation');
const { exec, execFile } = require('child_process');
const util = require('util');
const fs = require('fs');
const execPromise = util.promisify(exec);
const execFilePromise = util.promisify(execFile);

// Configuración de lo que queremos monitorear
const valueObject = {
  cpuCurrentSpeed: 'min, max, avg, cores',
  cpu: 'manufacturer, brand, speed, cores, physicalCores',
  mem: 'total, free, used, active, available',
  currentLoad: 'currentLoad, currentLoadUser, currentLoadSystem, cpus',
  fsSize: 'fs, type, size, used, available, mount',
  networkStats: 'iface, rx_bytes, tx_bytes, rx_sec, tx_sec',
  processes: 'all, running, blocked, sleeping' // Resumen de procesos
};

/**
 * Obtiene métricas estáticas del sistema (Hardware, OS)
 * Se ejecuta una sola vez al inicio.
 */
async function getStaticData() {
  try {
    const osInfo = await si.osInfo();
    const system = await si.system();
    const cpu = await si.cpu();
    const networkInterfaces = await si.networkInterfaces();
    
    // Simplificar interfaces
    const interfaces = Array.isArray(networkInterfaces) 
      ? networkInterfaces.map(iface => ({
          iface: iface.iface,
          ip4: iface.ip4,
          mac: iface.mac,
          type: iface.type,
          operstate: iface.operstate
        }))
      : [];

    return {
      os: {
        platform: osInfo.platform,
        distro: osInfo.distro,
        release: osInfo.release,
        hostname: osInfo.hostname
      },
      hardware: {
        manufacturer: system.manufacturer,
        model: system.model,
        cpu: `${cpu.manufacturer} ${cpu.brand}`,
        cores: cpu.cores
      },
      network: {
        interfaces
      }
    };
  } catch (e) {
    console.error('Error obteniendo datos estáticos:', e);
    return {};
  }
}

/**
 * Obtiene métricas dinámicas (CPU, RAM, Disco, Red, Procesos)
 */
async function getDynamicData() {
  try {
    const data = await si.get({
      currentLoad: 'currentLoad, currentLoadUser, currentLoadSystem',
      mem: 'total, free, used, active, available',
      fsSize: 'fs, type, size, used, available, mount',
      networkStats: 'iface, rx_bytes, tx_bytes, rx_sec, tx_sec',
      processes: 'all, running, blocked, sleeping, list' 
    });

    if (data.processes && data.processes.list) {
      data.processes.top10 = data.processes.list
        .sort((a, b) => b.cpu - a.cpu)
        .slice(0, 10)
        .map(p => ({
          pid: p.pid,
          name: p.name,
          cpu: p.cpu.toFixed(2),
          mem: p.mem.toFixed(2),
          user: p.user
        }));
      delete data.processes.list;
    }

    return {
      timestamp: new Date().toISOString(),
      metrics: data
    };
  } catch (e) {
    console.error('Error obteniendo métricas dinámicas:', e);
    return null;
  }
}

/**
 * Obtiene conexiones de red activas (Listening & Established)
 * "Mapeo de red" local
 */
async function getNetworkConnections() {
  try {
    const connections = await si.networkConnections();
    // Filtramos para mostrar solo lo interesante: LISTEN y ESTABLISHED
    // y excluimos conexiones locales unix sockets si hay demasiadas
    return connections
      .filter(c => c.protocol === 'tcp' || c.protocol === 'udp')
      .map(c => ({
        protocol: c.protocol,
        localAddress: c.localAddress,
        localPort: c.localPort,
        peerAddress: c.peerAddress,
        peerPort: c.peerPort,
        state: c.state,
        process: c.process // Nombre del proceso si tenemos permisos (root)
      }));
  } catch (e) {
    console.error('Error obteniendo conexiones de red:', e);
    return [];
  }
}

/**
 * Analiza logs de SSH para detectar intentos de intrusión y accesos
 * Específico para Linux (/var/log/auth.log o /var/log/secure)
 */
async function getSshActivity() {
  // Detectar archivo de logs según distro
  let logFile = '/var/log/auth.log'; // Debian/Ubuntu
  if (fs.existsSync('/var/log/secure')) {
    logFile = '/var/log/secure'; // RHEL/CentOS/Fedora
  }

  // Si no estamos en Linux o no existe el archivo (ej. Windows dev), retornamos mock o info
  if (process.platform !== 'linux' || !fs.existsSync(logFile)) {
    return {
      status: 'unavailable',
      message: 'SSH logs not found or OS not supported (Linux required)',
      platform: process.platform
    };
  }

  try {
    // Usamos 'tail' nativo de Linux para eficiencia. Leer ultimas 100 lineas.
    // Esto es mucho más eficiente que leer todo el archivo con Node.
    const { stdout } = await execPromise(`tail -n 100 ${logFile}`);
    const lines = stdout.split('\n').reverse(); // Más recientes primero

    const activity = {
      failed_attempts: [],
      successful_logins: [],
      sudo_usage: []
    };

    lines.forEach(line => {
      if (!line) return;

      // Detectar Failed Password
      if (line.includes('Failed password')) {
        // Ejemplo: Feb 11 10:00:00 host sshd[123]: Failed password for root from 192.168.1.50 port 22 ssh2
        const match = line.match(/Failed password for (invalid user )?(\w+) from ([\d\.]+) port (\d+)/);
        if (match) {
          activity.failed_attempts.push({
            raw: line,
            user: match[2],
            ip: match[3],
            port: match[4],
            timestamp: line.substring(0, 15) // Aprox, depende del formato syslog
          });
        }
      }
      
      // Detectar Accepted Password / Publickey
      else if (line.includes('Accepted')) {
        const match = line.match(/Accepted (password|publickey) for (\w+) from ([\d\.]+) port (\d+)/);
        if (match) {
          activity.successful_logins.push({
            method: match[1],
            user: match[2],
            ip: match[3],
            timestamp: line.substring(0, 15)
          });
        }
      }

      // Detectar uso de SUDO
      else if (line.includes('sudo:') && line.includes('COMMAND=')) {
        activity.sudo_usage.push({
           raw: line.substring(0, 100) + '...' // Truncar por seguridad
        });
      }
    });

    return {
      status: 'active',
      log_file: logFile,
      summary: {
        failed_count: activity.failed_attempts.length,
        success_count: activity.successful_logins.length
      },
      details: activity
    };

  } catch (e) {
    return {
      status: 'error',
      message: 'Error reading SSH logs. Ensure agent has root/read permissions.',
      error: e.message
    };
  }
}

/**
 * Obtiene estado de contenedores Docker
 */
async function getDockerStats() {
  try {
    const containers = await si.dockerContainers();
    const info = await si.dockerInfo();
    
    // Resumen simplificado
    return {
      info: {
        containers: info.containers,
        running: info.containersRunning,
        paused: info.containersPaused,
        stopped: info.containersStopped,
        images: info.images
      },
      containers: containers.map(c => ({
        id: c.id.substring(0, 12),
        name: c.name,
        image: c.image,
        state: c.state,
        status: c.status,
        created: c.createdAt,
        ports: c.ports
      }))
    };
  } catch (e) {
    // Docker puede no estar instalado o sin permisos
    return { 
      available: false, 
      error: 'Docker not found or permission denied (ensure user is in docker group)' 
    };
  }
}

/**
 * Obtiene logs de un contenedor Docker
 */
async function getDockerLogs(containerId, lines = 50) {
  // Validación básica para evitar inyección
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(containerId)) {
    throw new Error('Invalid container ID');
  }
  const lineCount = parseInt(lines) || 50;

  try {
    const { stdout, stderr } = await execFilePromise('docker', ['logs', '--tail', lineCount.toString(), containerId]);
    // Docker escribe logs a stdout y stderr indistintamente a veces
    return stdout || stderr; 
  } catch (e) {
    return `Error retrieving logs: ${e.message}`;
  }
}

/**
 * Obtiene inspección detallada de un contenedor (Complex Status)
 */
async function getDockerInspect(containerId) {
   if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(containerId)) {
    throw new Error('Invalid container ID');
  }
  try {
    const { stdout } = await execFilePromise('docker', ['inspect', containerId]);
    return JSON.parse(stdout)[0];
  } catch (e) {
    return { error: e.message };
  }
}

/**
 * Obtiene usuarios conectados al sistema
 */
async function getUsers() {
  try {
    const users = await si.users();
    return users;
  } catch (e) {
    return [];
  }
}

/**
 * Obtiene estado de servicios (Systemd)
 */
async function getServices(serviceList = '*') {
  try {
    const services = await si.services(serviceList);
    return services.map(s => ({
      name: s.name,
      running: s.running,
      startmode: s.startmode,
      pids: s.pids
    }));
  } catch (e) {
    return { error: 'Failed to get services info' };
  }
}

/**
 * Obtiene logs de un servicio Systemd (journalctl)
 */
async function getServiceLogs(serviceName, lines = 50) {
  // Validación estricta para nombre de servicio
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-@]*$/.test(serviceName)) {
    throw new Error('Invalid service name');
  }
  const lineCount = parseInt(lines) || 50;

  try {
    // -u para unidad, --no-pager para texto plano, -n para líneas
    const { stdout } = await execFilePromise('journalctl', ['-u', serviceName, '-n', lineCount.toString(), '--no-pager']);
    return stdout;
  } catch (e) {
    return `Error retrieving service logs: ${e.message}`;
  }
}

/**
 * Obtiene status completo de systemd (systemctl status)
 */
async function getServiceStatusDetailed(serviceName) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-@]*$/.test(serviceName)) {
    throw new Error('Invalid service name');
  }
  try {
    const { stdout } = await execFilePromise('systemctl', ['status', serviceName, '--no-pager']);
    return stdout;
  } catch (e) {
    // systemctl status retorna exit code no-cero si el servicio está fallando, pero queremos el output igual para diagnosticar
    return e.stdout || e.message;
  }
}

module.exports = {
  getStaticData,
  getDynamicData,
  getNetworkConnections,
  getSshActivity,
  getDockerStats,
  getDockerLogs,
  getDockerInspect,
  getUsers,
  getServices,
  getServiceLogs,
  getServiceStatusDetailed
};
