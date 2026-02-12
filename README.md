# Agente de Monitoreo & API (Node.js)

Este agente ligero expone métricas del sistema, auditoría de seguridad SSH, mapeo de red y herramientas de SysAdmin (Docker, Servicios, Archivos) a través de una API REST de alto rendimiento (Fastify).

## Arquitectura

- **Core**: Node.js + `systeminformation` (Interacción con Kernel/OS).
- **Seguridad**: 
    - Parseo nativo de logs de autenticación.
    - Auditoría automática (Score).
    - Mapa de amenazas (Geolocalización IP).
- **SysAdmin**: Monitoreo de Docker, Systemd y Gestión de Archivos.

## Requisitos

- Node.js (v14 o superior).
- **Linux**: Permisos de lectura en `/var/log/auth.log` (o root) para auditoría SSH y `ufw`.
- **Docker**: Usuario debe pertenecer al grupo `docker`.

## Instalación

1. Instalar dependencias:
   ```bash
   npm install
   ```

## Uso

Iniciar el agente:
```bash
sudo node index.js
```

Para producción (PM2):
```bash
npm install -g pm2
sudo pm2 start index.js --name "monitor-agent"
```

## API Endpoints

Puerto default: `3456`. Header Auth: `x-api-key: secret-agent-key`.

### 1. Métricas & Sistema
- `GET /health` (Público): Estado del servicio.
- `GET /metrics` (Auth): CPU, RAM, Disco, Top Procesos.
- `GET /system` (Auth): Hardware y OS.

### 2. Seguridad Avanzada
- `GET /security/audit`: Puntuación de Seguridad (0-100).
- `GET /network/map`: Mapa de Amenazas (Geolocalización).
- `GET /security/ssh`: Auditoría de logs SSH.
- `GET /network/connections`: Tabla de conexiones.

### 3. Herramientas SysAdmin
#### Docker & Servicios
- `GET /system/docker`: Lista de contenedores.
- `GET /system/docker/:id/inspect`: Detalle JSON de contenedor.
- `GET /system/docker/:id/logs`: Logs de contenedor.
- `GET /system/services?name=nginx`: Estado de servicio.
- `GET /system/services/:name/status`: Status detallado systemctl.
- `GET /system/services/:name/logs`: Logs journalctl.

#### Sistema de Archivos (NUEVO)
- `GET /system/files/large`: Buscar archivos pesados.
    - Params: `path=/var/log`, `min=100M`, `limit=10`.
- `DELETE /system/files`: Eliminar archivo.
    - Body: `{ "path": "/path/to/file.log" }`.
    - **Nota**: Protegido contra eliminación de archivos críticos del sistema.

#### Usuarios
- `GET /system/users`: Usuarios conectados.

## Configuración
Variables de entorno en `.env`:
- `PORT`: Puerto (3456).
- `API_KEY`: Clave de seguridad.
