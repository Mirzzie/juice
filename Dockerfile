# FROM bkimminich/juice-shop:latest

# # Install Datadog tracing library
# RUN npm install dd-trace@latest

# # Ensure tracing starts before the app
# CMD ["node", "-r", "dd-trace/init", "server.js"]

# --- Stage 1: Build Juice Shop ---

# Use Node.js base image (Juice Shop requires Node 18+)
FROM node:18

# Set working directory
WORKDIR /app

# Copy package.json & lock file first (for better caching)
COPY package*.json ./

# Install dependencies (including Datadog tracer)
RUN npm install && npm install dd-trace@latest

# Copy rest of Juice Shop source
COPY . .

# Expose Juice Shop default port
EXPOSE 3000

# Start Juice Shop with Datadog tracer enabled
CMD ["node", "-r", "dd-trace/init", "server.js"]
