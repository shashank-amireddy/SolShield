FROM node:18-alpine

# Install system dependencies for security tools
RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    build-base \
    python3-dev \
    libffi-dev \
    openssl-dev

# Install security analysis tools
RUN pip3 install slither-analyzer mythril

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S scanner -u 1001

# Change ownership of the app directory
RUN chown -R scanner:nodejs /app
USER scanner

# Expose port (if needed for future web interface)
EXPOSE 3000

# Set the entrypoint
ENTRYPOINT ["node", "dist/index.js"]