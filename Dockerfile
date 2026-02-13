# Etapa 1: Construcción y Dependencias
FROM node:18-alpine AS builder

WORKDIR /app

# Instalar dependencias de compilación para paquetes nativos (systeminformation, node-rsa)
RUN apk add --no-cache python3 make g++ linux-headers

COPY package*.json ./
RUN npm ci --only=production

# Etapa 2: Imagen Final Ligera
FROM node:18-alpine

WORKDIR /app

# Instalar utilidades del sistema necesarias para el monitoreo (docker cli, util-linux, etc.)
# Nota: El agente necesita interactuar con el host, por lo que requerirá montar sockets y volúmenes
RUN apk add --no-cache \
    docker-cli \
    util-linux \
    iproute2 \
    openssh-client \
    bash

COPY --from=builder /app/node_modules ./node_modules
COPY . .

# Crear directorios para persistencia segura
RUN mkdir -p secure && chmod 700 secure

# Exponer puerto
EXPOSE 3456

# Comando de inicio
CMD ["node", "index.js"]
