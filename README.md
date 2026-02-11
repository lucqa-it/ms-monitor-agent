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

## Colección Postman

Se incluye un archivo `monitor-agent.postman_collection.json` en la raíz del proyecto.

## API Endpoints

Puerto default: `3456`. Header Auth: `x-api-key: secret-agent-key`.

### 1. Métricas Generales
- `GET /health` (Público): Estado del servicio.
- `GET /metrics` (Auth): CPU, RAM, Disco, Top Procesos.
- `GET /system` (Auth): Hardware y OS.

### 2. Seguridad & Red
- `GET /security/ssh`: Auditoría de logs de autenticación (Brute force detection).
- `GET /network/connections`: Tabla de conexiones activas y puertos escuchando.

### 3. Herramientas SysAdmin (Avanzado)

#### Docker
- `GET /system/docker`: Lista de contenedores.
- `GET /system/docker/:id/inspect`: (NUEVO) JSON completo de `docker inspect`.
- `GET /system/docker/:id/logs`: (NUEVO) Últimas líneas de logs (`?lines=50`).

#### Servicios (Systemd)
- `GET /system/services?name=nginx`: Estado simple (running/stopped).
- `GET /system/services/:name/status`: (NUEVO) Salida completa de `systemctl status`.
- `GET /system/services/:name/logs`: (NUEVO) Logs recientes de journalctl (`?lines=50`).

#### Usuarios
- `GET /system/users`: Usuarios conectados.

## Configuración
Variables de entorno en `.env`:
- `PORT`: Puerto (3456).
- `API_KEY`: Clave de seguridad.
