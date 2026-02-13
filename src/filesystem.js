const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const execPromise = util.promisify(exec);

function parseAllowedRoots() {
  const raw = process.env.FS_ALLOWED_ROOTS;
  if (raw && raw.trim()) {
    return raw
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
      .map(p => path.resolve(p));
  }
  if (process.platform === 'win32') {
    return [path.resolve(process.cwd())];
  }
  return ['/var/log', '/tmp', '/opt'].map(p => path.resolve(p));
}

function normalizeForCompare(p) {
  const resolved = path.resolve(p);
  if (process.platform === 'win32') {
    return resolved.toLowerCase();
  }
  return resolved;
}

function isSubPath(childPath, parentPath) {
  const child = normalizeForCompare(childPath);
  const parent = normalizeForCompare(parentPath);
  if (child === parent) return true;
  const sep = process.platform === 'win32' ? '\\' : '/';
  const prefix = parent.endsWith(sep) ? parent : parent + sep;
  return child.startsWith(prefix);
}

function assertPathAllowed(inputPath) {
  if (!inputPath || typeof inputPath !== 'string') {
    throw new Error('Path is required');
  }

  const resolved = path.resolve(inputPath);
  let real = resolved;
  try {
    if (fs.existsSync(resolved)) {
      real = fs.realpathSync(resolved);
    }
  } catch (e) {
    real = resolved;
  }

  const forbiddenPrefixes = process.platform === 'win32'
    ? [path.resolve(process.cwd())]
    : ['/bin', '/boot', '/dev', '/etc', '/lib', '/proc', '/sys', '/usr/bin', '/usr/lib', '/run'].map(p => path.resolve(p));

  const secureDir = path.resolve(path.join(process.cwd(), 'secure'));
  if (isSubPath(resolved, secureDir) || isSubPath(real, secureDir)) {
    throw new Error('Access to secure directory is forbidden');
  }

  for (const prefix of forbiddenPrefixes) {
    if (process.platform !== 'win32' && (isSubPath(resolved, prefix) || isSubPath(real, prefix))) {
      throw new Error('Access to system critical paths is forbidden');
    }
  }

  const allowedRoots = parseAllowedRoots();
  const allowed = allowedRoots.some(root => isSubPath(resolved, root) || isSubPath(real, root));
  if (!allowed) {
    throw new Error(`Path not allowed. Configure FS_ALLOWED_ROOTS if needed.`);
  }

  return resolved;
}

/**
 * Busca archivos pesados en un directorio específico
 * @param {string} dirPath - Directorio a escanear (default: /var)
 * @param {string} minSize - Tamaño mínimo (ej: 100M, 1G)
 * @param {number} limit - Cantidad de archivos a retornar
 */
async function findLargeFiles(dirPath = '/var', minSize = '100M', limit = 10) {
  // Validar path para evitar inyección de comandos simple
  if (!/^[a-zA-Z0-9_\-\/\.]+$/.test(dirPath)) {
    throw new Error('Invalid path characters');
  }
  
  // Normalizar path
  const targetPath = path.resolve(dirPath);
  
  // En Windows (Dev), simulamos o usamos PowerShell
  if (process.platform === 'win32') {
    // Implementación básica para Windows usando PowerShell
    // Get-ChildItem -Path "C:\Path" -Recurse -File | Where-Object { $_.Length -gt 100MB } | Sort-Object Length -Descending | Select-Object -First 10
    return { error: 'Large file search optimized for Linux. Windows support is experimental.' };
  }

  // Comando Linux optimizado: find + printf + sort + head
  // -type f: solo archivos
  // -size: tamaño mínimo
  // -printf: imprimir tamaño (bytes) y path
  const cmd = `find "${targetPath}" -type f -size +${minSize} -printf '%s %p\n' 2>/dev/null | sort -nr | head -n ${limit}`;

  try {
    const { stdout } = await execPromise(cmd);
    const files = stdout.trim().split('\n').filter(line => line).map(line => {
      const parts = line.trim().split(/\s+/);
      const sizeBytes = parseInt(parts[0]);
      const filePath = parts.slice(1).join(' '); // Re-join por si el path tiene espacios
      return {
        path: filePath,
        sizeBytes: sizeBytes,
        sizeHuman: (sizeBytes / (1024 * 1024)).toFixed(2) + ' MB'
      };
    });
    return files;
  } catch (e) {
    // find retorna exit code 1 si hay errores de permiso en algunos subdirectorios, 
    // pero igual puede haber encontrado cosas. Si stderr es crítico, lo lanzamos.
    return { error: e.message, hint: 'Ensure agent has read permissions on target directory' };
  }
}

/**
 * Elimina un archivo específico
 * @param {string} filePath - Ruta absoluta del archivo
 */
async function deleteFile(filePath) {
  const resolvedPath = path.resolve(filePath);

  // 1. Validaciones de Seguridad Críticas
  
  // No permitir borrar raíz o directorios críticos del sistema ciegamente
  const forbiddenPrefixes = ['/bin', '/boot', '/dev', '/etc', '/lib', '/proc', '/sys', '/usr/bin', '/usr/lib'];
  if (forbiddenPrefixes.some(prefix => resolvedPath.startsWith(prefix))) {
    throw new Error('Deletion of system critical files is forbidden via this agent');
  }

  // No permitir borrar el propio agente
  if (resolvedPath.includes(process.cwd())) {
    throw new Error('Cannot delete agent files');
  }

  const secureDir = path.resolve(path.join(process.cwd(), 'secure'));
  if (resolvedPath.includes(secureDir)) {
    throw new Error('Cannot delete secure files');
  }

  // Verificar que existe y es un archivo (no directorio)
  try {
    const stats = fs.lstatSync(resolvedPath);
    if (!stats.isFile()) {
      throw new Error('Target is not a file');
    }
  } catch (e) {
    throw new Error('File not found or not accessible');
  }

  // Proceder a eliminar
  try {
    fs.unlinkSync(resolvedPath);
    return { success: true, message: `File ${resolvedPath} deleted successfully` };
  } catch (e) {
    throw new Error(`Failed to delete file: ${e.message}`);
  }
}

async function listDirectory(dirPath, options = {}) {
  const limit = Number.isFinite(Number(options.limit)) ? Math.max(1, Math.min(1000, Number(options.limit))) : 200;
  const offset = Number.isFinite(Number(options.offset)) ? Math.max(0, Number(options.offset)) : 0;
  const targetPath = assertPathAllowed(dirPath);

  const secureDir = path.resolve(path.join(process.cwd(), 'secure'));
  const hiddenNames = new Set(['secure', '.env', '.env.local', '.git', 'node_modules']);

  const st = fs.statSync(targetPath);
  if (!st.isDirectory()) {
    throw new Error('Target is not a directory');
  }

  const entries = fs.readdirSync(targetPath, { withFileTypes: true });
  const sorted = entries
    .filter((d) => {
      if (hiddenNames.has(d.name)) return false;
      const fullPath = path.join(targetPath, d.name);
      return !isSubPath(fullPath, secureDir);
    })
    .map((d) => {
      const fullPath = path.join(targetPath, d.name);
      let s;
      try {
        s = fs.lstatSync(fullPath);
      } catch (e) {
        s = null;
      }

      const type = d.isDirectory() ? 'directory' : d.isFile() ? 'file' : d.isSymbolicLink() ? 'symlink' : 'other';
      return {
        name: d.name,
        path: fullPath,
        type,
        sizeBytes: s && s.isFile() ? s.size : null,
        mtimeMs: s ? s.mtimeMs : null,
        mode: s ? s.mode : null
      };
    })
    .sort((a, b) => {
      if (a.type !== b.type) {
        if (a.type === 'directory') return -1;
        if (b.type === 'directory') return 1;
      }
      return a.name.localeCompare(b.name);
    });

  const page = sorted.slice(offset, offset + limit);
  return {
    path: targetPath,
    total: sorted.length,
    offset,
    limit,
    items: page
  };
}

async function statPath(target) {
  const targetPath = assertPathAllowed(target);
  const s = fs.lstatSync(targetPath);
  return {
    path: targetPath,
    type: s.isDirectory() ? 'directory' : s.isFile() ? 'file' : s.isSymbolicLink() ? 'symlink' : 'other',
    sizeBytes: s.size,
    mtimeMs: s.mtimeMs,
    ctimeMs: s.ctimeMs,
    mode: s.mode
  };
}

async function readFileChunk(filePath, options = {}) {
  const targetPath = assertPathAllowed(filePath);
  const s = fs.statSync(targetPath);
  if (!s.isFile()) {
    throw new Error('Target is not a file');
  }

  const encoding = (options.encoding || 'utf8').toLowerCase();
  const maxBytes = Number.isFinite(Number(options.maxBytes)) ? Math.max(1, Math.min(1024 * 1024, Number(options.maxBytes))) : 64 * 1024;

  let start = 0;
  if (options.tailBytes != null) {
    const tailBytes = Math.max(1, Math.min(s.size, Number(options.tailBytes)));
    start = Math.max(0, s.size - tailBytes);
  } else if (options.offset != null) {
    start = Math.max(0, Math.min(s.size, Number(options.offset)));
  }

  const toRead = Math.min(maxBytes, Math.max(0, s.size - start));

  const fd = fs.openSync(targetPath, 'r');
  try {
    const buffer = Buffer.alloc(toRead);
    const bytesRead = fs.readSync(fd, buffer, 0, toRead, start);
    const slice = buffer.subarray(0, bytesRead);
    const data = encoding === 'base64' ? slice.toString('base64') : slice.toString('utf8');
    return {
      path: targetPath,
      sizeBytes: s.size,
      offset: start,
      bytesRead,
      encoding: encoding === 'base64' ? 'base64' : 'utf8',
      data
    };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = {
  findLargeFiles,
  deleteFile,
  listDirectory,
  statPath,
  readFileChunk
};
