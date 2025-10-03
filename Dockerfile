# Use full Node.js image to allow npm install
FROM node:18

# Set working directory
WORKDIR /opt/juice-shop

# Copy Juice Shop source
COPY . .

# Install Juice Shop deps + Datadog tracer
RUN npm install --omit=dev
RUN npm install dd-trace@latest

# Set Datadog environment variables
ENV DD_IAST_ENABLED=true \
    DD_LOGS_INJECTION=true \
    NODE_OPTIONS="--require dd-trace/init"

EXPOSE 3000

CMD ["node", "server.js"]
