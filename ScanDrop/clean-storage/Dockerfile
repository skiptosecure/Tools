FROM registry.access.redhat.com/ubi9/python-39:latest

USER root

# Update system
RUN dnf update -y && dnf clean all

# Set working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/storage /app/metadata /app/logs /app/ssl

# Set permissions
RUN chmod 777 /app/storage /app/metadata /app/logs

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install -r requirements.txt

# Copy SSL certificates
COPY ssl/ /app/ssl/

# Copy application code
COPY . .

# Set SSL certificate permissions
RUN chmod 644 /app/ssl/certificate.pem && chmod 600 /app/ssl/private-key.pem

# Expose HTTPS port
EXPOSE 8000

# Use Flask directly for HTTPS support
CMD ["python", "app.py"]