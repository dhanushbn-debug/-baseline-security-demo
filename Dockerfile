# Universal Production Dockerfile
FROM node:24-alpine

WORKDIR /app

# Copy application files
COPY package.json ./
COPY server.js ./
COPY server/ ./server/
COPY public/ ./public/
COPY data/ ./data/

# Set production environment
ENV NODE_ENV=production
ENV PORT=5000

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/api/health || exit 1

CMD ["node", "server.js"]
