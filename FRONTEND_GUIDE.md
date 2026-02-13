# 🔐 Guía de Integración Frontend (Secure Session)

Esta guía explica cómo conectar tu aplicación Frontend con el Agente de Monitoreo utilizando el sistema de **Token de Sesión Rotativo**.

## 🛡️ Concepto de Seguridad

1.  **Session Token**: El agente genera un token único cada vez que se reinicia (`sessionToken`). Este token vive solo en la memoria RAM del servidor.
2.  **Cifrado**: Tu frontend debe cifrar este token con la Clave Pública del servidor antes de enviarlo.
3.  **Seguridad**: No necesitas guardar la "Key Maestra" en tu código. Solo necesitas inyectar el `sessionToken` actual en tu frontend (vía variable de entorno o config en tiempo de despliegue).

---

## � Flujo de Implementación

### 1. Obtener el Token de Sesión
Cuando el agente arranca, verás esto en los logs del servidor:

```
🎟️  SESSION TOKEN GENERADO (Válido hasta reinicio):
   abc-123-def-456...
```

Copia este token. Es el que usarás en tu frontend. Si reinicias el agente, el token cambiará (rotación automática).

### 2. Configurar Frontend

```javascript
// Configuración (Inyectada en build time o runtime env)
const AGENT_SESSION_TOKEN = 'abc-123-def-456...'; // El token que copiaste
const API_URL = 'http://tu-servidor:3456';
```

### 3. Código de Cliente Seguro

```javascript
import forge from 'node-forge';

class SecureMonitorClient {
  private publicKeyPem = null;

  async request(endpoint) {
    // 1. Obtener Clave Pública (Handshake)
    if (!this.publicKeyPem) {
      const res = await fetch(`${API_URL}/auth/handshake`);
      const data = await res.json();
      this.publicKeyPem = data.publicKey;
    }

    // 2. Cifrar el Session Token
    const publicKey = forge.pki.publicKeyFromPem(this.publicKeyPem);
    const encryptedToken = publicKey.encrypt(AGENT_SESSION_TOKEN, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha1.create() }
    });
    const authHeader = forge.util.encode64(encryptedToken);

    // 3. Enviar Petición
    return fetch(`${API_URL}${endpoint}`, {
      headers: {
        'x-auth-secure': authHeader
      }
    }).then(r => r.json());
  }
}
```

## ✅ Ventajas

*   **Key Maestra Protegida**: La clave maestra nunca sale del servidor.
*   **Rotación**: Cada reinicio invalida los tokens anteriores automáticamente.
*   **Memoria**: El token de sesión no se escribe en disco, dificultando su robo forense.

