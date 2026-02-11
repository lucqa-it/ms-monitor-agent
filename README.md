# Agente de Monitoreo & API (Node.js)

Este agente ligero expone métricas del sistema, auditoría de seguridad SSH, mapeo de red y herramientas de SysAdmin (Docker, Servicios) a través de una API REST de alto rendimiento (Fastify).

## Arquitectura

- **Core**: Node.js + `systeminformation` (Interacción con Kernel/OS).
- **Seguridad**: 
    - Parseo nativo de logs de autenticación.
    - Auditoría automática (Score).
    - Mapa de amenazas (Geolocalización IP).
- **SysAdmin**: Monitoreo de Docker (Socket) y Systemd.

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

### 2. Seguridad Avanzada (NUEVO)
- `GET /security/audit`: **Puntuación de Seguridad (0-100)**.
    - Analiza configuración SSH, Firewall, usuario root y puertos expuestos.
    - Retorna hallazgos (High/Medium/Low) y grado (A-F).
- `GET /network/map`: **Mapa de Amenazas**.
    - Geolocaliza IPs conectadas al servidor (País, Ciudad, ISP).
    - Útil para visualizar origen de conexiones.
- `GET /security/ssh`: Auditoría de logs de autenticación (Brute force).
- `GET /network/connections`: Tabla de conexiones raw.

### 3. Herramientas SysAdmin
- `GET /system/docker`: Lista de contenedores.
- `GET /system/docker/:id/inspect`: Detalle JSON de contenedor.
- `GET /system/docker/:id/logs`: Logs de contenedor.
- `GET /system/services?name=nginx`: Estado de servicio.
- `GET /system/services/:name/status`: Status detallado systemctl.
- `GET /system/services/:name/logs`: Logs journalctl.
- `GET /system/users`: Usuarios conectados.

## Configuración
Variables de entorno en `.env`:
- `PORT`: Puerto (3456).
- `API_KEY`: Clave de seguridad.
