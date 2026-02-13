# 🕵️ Monitor Agent (Secure Edition)

Un agente de monitoreo ligero, modular y **altamente seguro** diseñado para servidores Linux de misión crítica. Expone métricas, auditoría de seguridad y herramientas de administración a través de una API REST protegida con **Cifrado E2E (RSA-2048)**.

## 🚀 Características Principales

*   **⚡ Rendimiento**: Basado en Fastify (Node.js), consumo mínimo de recursos.
*   **🔒 Seguridad Militar**: Autenticación con cifrado asimétrico RSA. Las credenciales nunca viajan en texto plano.
*   **🛡️ Auditoría Automática**: Escanea el servidor y otorga una puntuación de seguridad (Score A-F).
*   **🌍 Mapa de Amenazas**: Geolocalización en tiempo real de conexiones entrantes/salientes.
*   **🔧 SysAdmin Tools**: Gestión remota de Docker, Systemd y Archivos sin necesidad de SSH interactivo.

---

## 🐳 Despliegue Rápido (Docker)

Esta es la forma recomendada para entornos de producción.

### 1. Iniciar con Docker Compose
```bash
docker-compose up -d
```

### 2. Verificar Logs (Para obtener Session Token)
```bash
docker logs monitor-agent
```
Busca el mensaje: `🎟️ SESSION TOKEN GENERADO: xxxxxxxx-xxxx-xxxx...`

---

## 📦 Despliegue Standalone (Sin Node.js)

Puedes compilar el agente en un **ejecutable binario** único que no requiere instalar Node.js ni `npm` en el servidor destino.

### 1. Compilar
```bash
npm run build:bin
```
Esto generará el archivo `dist/monitor-agent-linux`.

### 2. Ejecutar en Servidor
Sube solo ese archivo y ejecútalo:
```bash
chmod +x monitor-agent-linux
./monitor-agent-linux
```

---

## 📦 Instalación Manual (Legacy)

### Requisitos
*   Node.js v14+
*   Linux (Ubuntu/Debian/CentOS/RHEL recomendados)

### 1. Clonar e Instalar
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

### 3. Iniciar
```bash
npm start
```

---

## 🔐 Seguridad y Autenticación E2E

Este agente implementa un **Handshake Criptográfico** con Token de Sesión Rotativo.

1.  **Handshake**: El cliente solicita la Clave Pública (`GET /auth/handshake`).
2.  **Token de Sesión**: El agente genera un token único en memoria al arrancar (ver logs).
3.  **Cifrado**: El cliente cifra ese token con la Clave Pública y lo envía en `x-auth-secure`.

**Ventaja**: Si reinicias el agente, el token anterior se invalida. Si te roban el código, no hay claves hardcodeadas.

## ⚙️ Configuración de Filesystem Explorer

El explorador de archivos restringe rutas por seguridad. Puedes ampliar/reducir lo permitido con:

- `FS_ALLOWED_ROOTS`: lista separada por comas de directorios permitidos (ej: `/var/log,/tmp,/opt`).

---

## 📡 API Endpoints

### 🟢 Estado y Métricas
| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/health` | Check de vida (Público). |
| `GET` | `/metrics` | CPU, RAM, Disco, Red en tiempo real. |

### 🛡️ Seguridad
| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/security/audit` | **Score de Seguridad (0-100)**. |
| `GET` | `/network/map` | Mapa de amenazas con geolocalización. |

### 🛠 Herramientas SysAdmin
| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/system/docker` | Listado de contenedores. |
| `GET` | `/system/services` | Estado de servicios Systemd. |
| `GET` | `/system/fs/list` | Listar directorios (explorador). |
| `GET` | `/system/fs/stat` | Metadata de archivo/directorio. |
| `GET` | `/system/fs/read` | Leer fragmento de archivo (preview). |
| `GET` | `/system/files/large` | Buscar archivos pesados. |
| `DELETE` | `/system/files` | Eliminar archivo. |

---

## 📄 Licencia
MIT License.
