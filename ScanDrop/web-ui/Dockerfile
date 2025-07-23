FROM registry.access.redhat.com/ubi9/nodejs-18:latest
USER root

# Security updates
RUN dnf update -y && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# Install OpenSSL for certificate support
RUN dnf install -y openssl

# Create non-root user
RUN groupadd -r webui && useradd -r -g webui webui

WORKDIR /app
COPY package*.json ./

# Install dependencies
RUN npm install --only=production && \
    npm audit fix && \
    npm cache clean --force

# Copy SSL certificates
COPY ssl/ /app/ssl/
RUN chown -R webui:webui /app/ssl

COPY . .
RUN chown -R webui:webui /app

USER webui
EXPOSE 3000

CMD ["node", "server.js"]
