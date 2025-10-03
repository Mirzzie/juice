# FROM bkimminich/juice-shop:latest

# # Install Datadog tracing library
# RUN npm install dd-trace@latest

# # Ensure tracing starts before the app
# CMD ["node", "-r", "dd-trace/init", "server.js"]

# --- Stage 1: Build Juice Shop ---
FROM node:18-alpine AS build

WORKDIR /app

# Install deps first (better caching)
COPY package*.json ./
RUN npm install --omit=dev

# Copy source
COPY . .

# Build Juice Shop (if it has a build step)
RUN npm run build || true

# --- Stage 2: Runtime with Datadog ---
FROM node:18-alpine

WORKDIR /app

# Copy built app from previous stage
COPY --from=build /app /app

# Install Datadog tracer for Node.js
RUN npm install dd-trace@latest --save

# Expose Juice Shop port
EXPOSE 3000

# Environment for Datadog IAST
ENV NODE_ENV=production
ENV DD_IAST_ENABLED=true
ENV DD_LOGS_INJECTION=true
ENV DD_RUNTIME_METRICS_ENABLED=true
ENV DD_TRACE_DEBUG=false

# Default CMD - start Node with Datadog tracer
CMD ["node", "-r", "dd-trace/init", "server.js"]
