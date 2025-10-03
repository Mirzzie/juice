# Minimal wrapper over official Juice Shop
FROM bkimminich/juice-shop:latest

# Install Datadog tracer
USER root
RUN npm install dd-trace@latest --prefix /opt/juice-shop

# Set environment variables defaults (can override at runtime)
ENV DD_IAST_ENABLED=true \
    DD_LOGS_INJECTION=true

# Preload Datadog tracer
ENV NODE_OPTIONS="--require dd-trace/init"

# Expose port
EXPOSE 3000

# Start app
CMD ["node", "server.js"]
