FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency files
COPY package.json ./

# Install production dependencies
RUN npm install --omit=dev

# Copy application source code
COPY server.js ./
COPY frontend/ ./frontend/

# Expose container port
EXPOSE 3000

# Set environment defaults
ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/app/data

# Run application
CMD ["node", "server.js"]
