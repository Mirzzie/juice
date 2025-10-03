FROM bkimminich/juice-shop:latest

# Install Datadog tracing library
RUN npm install dd-trace@latest

# Ensure tracing starts before the app
CMD ["node", "-r", "dd-trace/init", "server.js"]