const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const execPromise = util.promisify(exec);

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

module.exports = {
  findLargeFiles,
  deleteFile
};
