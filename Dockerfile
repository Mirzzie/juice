# Minimal wrapper over official Juice Shop
FROM bkimminich/juice-shop:latest

# Set environment variables for Datadog
ENV DD_IAST_ENABLED=true \
    DD_LOGS_INJECTION=true \
    NODE_OPTIONS="--require dd-trace/init"

# Expose Juice Shop port
EXPOSE 3000

# Start the app
CMD ["node", "server.js"]

