# Minimal wrapper over official Juice Shop
FROM bkimminich/juice-shop:latest

# Switch to root to install dd-trace
USER root

# Install Datadog tracer globally
RUN npm install -g dd-trace@latest

# Set environment variables defaults (can override at runtime)
ENV DD_IAST_ENABLED=true \
    DD_LOGS_INJECTION=true \
    NODE_OPTIONS="--require dd-trace/init"

# Expose port
EXPOSE 3000

# Start Juice Shop
CMD ["node", "server.js"]
