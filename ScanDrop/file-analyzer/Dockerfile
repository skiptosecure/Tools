FROM registry.access.redhat.com/ubi9/python-39:latest

# Just run as root - forget security for now
USER root

RUN dnf update -y && dnf clean all

WORKDIR /app

# Create directories as root
RUN mkdir -p /app/uploads /app/logs
RUN chmod 777 /app/uploads /app/logs

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Run as root
EXPOSE 5000
CMD ["python", "app.py"]
