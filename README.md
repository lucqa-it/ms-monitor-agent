# 🕵️ Monitor Agent (Secure Edition)

Un agente de monitoreo ligero, modular y **altamente seguro** diseñado para servidores Linux de misión crítica. Expone métricas, auditoría de seguridad y herramientas de administración a través de una API REST protegida con **Cifrado E2E (RSA-2048)**.

## 🚀 Características Principales

*   **⚡ Rendimiento**: Basado en Fastify (Node.js), consumo mínimo de recursos.
*   **🔒 Seguridad Militar**: Autenticación con cifrado asimétrico RSA. Las credenciales nunca viajan en texto plano.
*   **🛡️ Auditoría Automática**: Escanea el servidor y otorga una puntuación de seguridad (Score A-F) basada en Firewall, SSH y puertos.
*   **🌍 Mapa de Amenazas**: Geolocalización en tiempo real de conexiones entrantes/salientes.
*   **🔧 SysAdmin Tools**: Gestión remota de Docker, Systemd y Archivos sin necesidad de SSH interactivo.

---

## 📦 Instalación

### Requisitos
*   Node.js v14+
*   Linux (Ubuntu/Debian/CentOS/RHEL recomendados)
*   Usuario con privilegios limitados (no root recomendado)

### 1. Clonar y Preparar
```bash
git clone https://github.com/tu-repo/monitor-agent.git
cd monitor-agent
npm install
```

### 2. Configuración de Permisos (Importante)
Para que el agente pueda auditar el firewall y logs sin ser `root`, agrega esto a tu `/etc/sudoers` (`sudo visudo`):

```bash
# Reemplaza 'monitor-user' por tu usuario real
monitor-user ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L*, /usr/sbin/nft list ruleset, /usr/sbin/ufw status
```

### 3. Iniciar Agente
```bash
# Iniciar en modo producción
npm start

# O usando PM2 (Recomendado)
npm install -g pm2
pm2 start index.js --name "monitor-agent"
```

> **Nota**: Al iniciar por primera vez, el agente generará un par de claves RSA en la carpeta `secure/` y mostrará tu **API Key Maestra** en la consola. ¡Guárdala!

---

## 🔐 Seguridad y Autenticación E2E

Este agente no utiliza API Keys planas tradicionales. Implementa un handshake criptográfico:

1.  **Handshake**: El cliente solicita la Clave Pública del servidor.
2.  **Cifrado**: El cliente cifra su API Key con dicha clave pública (RSA-OAEP).
3.  **Envío**: El cliente envía el token cifrado en el header `x-auth-secure`.

### Flujo de Ejemplo (Cliente)

```http
GET /auth/handshake
< 200 OK { "publicKey": "-----BEGIN PUBLIC KEY..." }

// Cifrar API_KEY localmente...

GET /system
x-auth-secure: <TOKEN_CIFRADO_BASE64>
< 200 OK { ... }
```

---

## 📡 API Endpoints

### 🟢 Estado y Métricas
| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/health` | Check de vida (Público). |
| `GET` | `/system` | Info de Hardware y OS. |
| `GET` | `/metrics` | CPU, RAM, Disco, Red en tiempo real. |

### 🛡️ Seguridad
| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/security/audit` | **Score de Seguridad (0-100)** y hallazgos de vulnerabilidades. |
| `GET` | `/network/map` | Mapa de amenazas con geolocalización de IPs. |
| `GET` | `/network/connections` | Tabla de conexiones TCP/UDP activas. |
| `GET` | `/security/ssh` | Intentos de intrusión (Brute force) en logs SSH. |

### 🛠 Herramientas SysAdmin
| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/system/docker` | Listado de contenedores. |
| `GET` | `/system/docker/:id/logs` | Ver logs de un contenedor. |
| `GET` | `/system/services` | Estado de servicios Systemd. |
| `GET` | `/system/files/large` | Buscar archivos pesados (`?path=/var&min=100M`). |
| `DELETE` | `/system/files` | Eliminar archivo (Protegido contra rutas críticas). |

---

## 🧪 Testing con Postman

Se incluye una colección lista para usar (`monitor-agent.postman_collection.json`) con scripts automáticos de cifrado.

1.  Importa la colección en Postman.
2.  Configura la variable `baseUrl` (ej: `http://tu-servidor:3456`) y `apiKey`.
3.  Ejecuta la petición **"Handshake"** una vez.
4.  ¡Listo! El resto de peticiones se firmarán automáticamente.

---

## ⚠️ Variables de Entorno (.env)

| Variable | Default | Descripción |
| :--- | :--- | :--- |
| `PORT` | `3456` | Puerto de escucha. |
| `HOST` | `0.0.0.0` | Interfaz de red. |
| `LOG_LEVEL` | `info` | Nivel de detalle de logs. |

---

## 📄 Licencia
MIT License.
