# FROM bkimminich/juice-shop:latest

# # Install Datadog tracing library
# RUN npm install dd-trace@latest

# # Ensure tracing starts before the app
# CMD ["node", "-r", "dd-trace/init", "server.js"]

# --- Stage 1: Build Juice Shop ---

# Use Node.js base image (Juice Shop requires Node 18+)

FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy only package files first (for caching)
COPY package*.json ./

# Install dependencies including Datadog tracer
RUN npm install
RUN npm install dd-trace@latest

# Copy rest of the app source
COPY . .

# Set Datadog env vars defaults (can override at runtime)
ENV DD_IAST_ENABLED=true \
    DD_LOGS_INJECTION=true

# Expose port
EXPOSE 3000

# Start app with Datadog tracer
CMD ["node", "-r", "dd-trace/init", "app.js"]
