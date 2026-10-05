FROM node:20-bookworm

# Install Python and native build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Node dependencies first for better Docker layer caching
COPY package.json package-lock.json ./
COPY server/package.json server/package.json
COPY client/package.json client/package.json

RUN npm ci

# Install Python dependencies in an isolated environment
COPY ml/requirements.txt ml/requirements.txt

RUN python3 -m venv /opt/mailsherlock-venv \
    && /opt/mailsherlock-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/mailsherlock-venv/bin/pip install --no-cache-dir -r ml/requirements.txt

ENV PATH="/opt/mailsherlock-venv/bin:$PATH"

# Copy the application source
COPY . .

# Build the production server and React frontend
RUN npm run build

# Production configuration
ENV NODE_ENV=production
ENV PORT=8080
ENV ML_PORT=8001
ENV DATABASE_PATH=/data/mailsherlock.sqlite
ENV STORE_RAW_SOURCE=true

# The public HTTP service listens on this port
EXPOSE 8080

# Start Python ML service and Node/Express API
CMD ["bash", "docker-entrypoint.sh"]
