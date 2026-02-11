# Agente de Monitoreo & API (Node.js)

Este agente ligero expone métricas del sistema, auditoría de seguridad SSH, mapeo de red y herramientas de SysAdmin (Docker, Servicios) a través de una API REST de alto rendimiento (Fastify).

## Arquitectura

- **Core**: Node.js + `systeminformation` (Interacción con Kernel/OS).
- **Seguridad**: Parseo nativo de logs de autenticación (Linux) y control de acceso API Key.
- **Red**: Análisis de tabla de conexiones TCP/UDP.
- **SysAdmin**: Monitoreo de Docker (Socket) y Systemd.

## Requisitos

- Node.js (v14 o superior).
- **Linux**: Permisos de lectura en `/var/log/auth.log` (o root) para auditoría SSH.
- **Docker**: Usuario debe pertenecer al grupo `docker` para ver métricas de contenedores.

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

### 1. Métricas Generales
- `GET /health` (Público): Estado del servicio.
- `GET /metrics` (Auth): CPU, RAM, Disco, Top Procesos.
- `GET /system` (Auth): Hardware y OS.

### 2. Seguridad & Red
- `GET /security/ssh`: Auditoría de logs de autenticación (Brute force detection).
- `GET /network/connections`: Tabla de conexiones activas y puertos escuchando.

### 3. Herramientas SysAdmin
Nuevos endpoints para administración avanzada:

#### Docker Stats
- **GET** `/system/docker`
- **Descripción**: Resumen de contenedores corriendo, imágenes y estado detallado de cada contenedor.
```json
{
  "data": {
    "info": { "running": 2, "stopped": 0, "images": 5 },
    "containers": [
      { "name": "nginx_proxy", "state": "running", "image": "nginx:latest", "ports": [...] }
    ]
  }
}
```

#### Servicios (Systemd/Init)
- **GET** `/system/services?name=nginx`
- **Query Param**: `name` (nombre del servicio o `*` para todos).
- **Descripción**: Verifica si un servicio crítico está corriendo.
```json
{
  "services": [
    { "name": "nginx", "running": true, "pids": [1234] }
  ]
}
```

#### Usuarios Conectados
- **GET** `/system/users`
- **Descripción**: Lista usuarios logueados actualmente (TTY/SSH).
```json
{
  "count": 1,
  "users": [
    { "user": "admin", "tty": "pts/0", "ip": "192.168.1.50" }
  ]
}
```

## Configuración
Variables de entorno en `.env`:
- `PORT`: Puerto (3456).
- `API_KEY`: Clave de seguridad.
