# Base official Juice Shop image
FROM bkimminich/juice-shop:latest

# Install dd-trace for Datadog instrumentation
RUN npm install dd-trace --save

# Environment variables for Datadog IAST and logs injection
ENV DD_IAST_ENABLED=true \
    DD_LOGS_INJECTION=true \
    NODE_OPTIONS="--require dd-trace/init"

# Expose application port
EXPOSE 3000

# Start the Juice Shop application
CMD ["node", "server.js"]
