#!/bin/bash

echo "============================================"
echo "SOC Tool Fresh System Installation Script"
echo "By skip to secure"
echo "============================================"

# Exit on any error
set -e

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "This script should not be run as root"
   exit 1
fi

# Detect OS
if [ -f /etc/redhat-release ]; then
    OS="rhel"
    echo "Detected: Red Hat/CentOS/Rocky Linux"
elif [ -f /etc/debian_version ]; then
    OS="debian"
    echo "Detected: Debian/Ubuntu"
else
    echo "Unsupported operating system"
    exit 1
fi

echo ""
echo "Step 1: Updating system packages..."
if [ "$OS" = "rhel" ]; then
    sudo dnf update -y
    sudo dnf install -y curl wget git unzip
elif [ "$OS" = "debian" ]; then
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y curl wget git unzip ca-certificates
fi

echo ""
echo "Step 2: Installing Docker..."
if [ "$OS" = "rhel" ]; then
    # Remove old Docker versions
    sudo dnf remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc
    
    # Add Docker repository
    sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    
    # Install Docker
    sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
elif [ "$OS" = "debian" ]; then
    # Remove old Docker versions
    sudo apt remove -y docker docker-engine docker.io containerd runc
    
    # Add Docker GPG key and repository
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update and install Docker
    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

echo ""
echo "Step 3: Configuring Docker..."
# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group
sudo usermod -aG docker $USER

echo ""
echo "Step 4: Installing Docker Compose (standalone)..."
# Get latest version
DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
sudo curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

echo ""
echo "Step 5: Installing Python and pip..."
if [ "$OS" = "rhel" ]; then
    sudo dnf install -y python3 python3-pip python3-devel
elif [ "$OS" = "debian" ]; then
    sudo apt install -y python3 python3-pip python3-dev
fi

echo ""
echo "Step 6: Installing OpenSSL for certificate generation..."
if [ "$OS" = "rhel" ]; then
    sudo dnf install -y openssl
elif [ "$OS" = "debian" ]; then
    sudo apt install -y openssl
fi

echo ""
echo "Step 7: Configuring firewall..."
if [ "$OS" = "rhel" ]; then
    # Configure firewalld
    sudo systemctl start firewalld
    sudo systemctl enable firewalld
    sudo firewall-cmd --permanent --add-port=3000/tcp
    sudo firewall-cmd --permanent --add-port=8000/tcp
    sudo firewall-cmd --reload
    echo "Firewall configured: opened ports 3000 and 8000"
elif [ "$OS" = "debian" ]; then
    # Configure ufw
    sudo ufw --force enable
    sudo ufw allow 3000/tcp
    sudo ufw allow 8000/tcp
    echo "Firewall configured: opened ports 3000 and 8000"
fi

echo ""
echo "Step 8: Cloning SOC Tool from GitHub..."
git clone https://github.com/skiptosecure/Tools.git
cd Tools/ScanDrop

echo ""
echo "Step 9: Generating SSL certificates..."
# Create SSL directories for all services
mkdir -p web-ui/ssl clean-storage/ssl file-analyzer/ssl

# Generate SSL certificates
cd web-ui/ssl
openssl req -x509 -newkey rsa:4096 -keyout private-key.pem -out certificate.pem -days 365 -nodes \
    -subj "/C=US/ST=Test/L=Test/O=SOC-Tool/OU=IT/CN=localhost"

# Copy SSL certificates to other services
cp private-key.pem certificate.pem ../../clean-storage/ssl/
cp private-key.pem certificate.pem ../../file-analyzer/ssl/

echo "✅ SSL certificates generated and copied to all services"
cd ../..

echo ""
echo "Step 10: Verifying installations..."

echo -n "Docker version: "
docker --version

echo -n "Docker Compose version: "
docker-compose --version

echo -n "Python version: "
python3 --version

echo -n "Pip version: "
pip3 --version

echo -n "OpenSSL version: "
openssl version

echo ""
echo "Step 12: Setting up VirusTotal API key placeholder..."
# Comment out VirusTotal API key requirement for testing
sed -i "s/VT_API_KEY = 'your_api_key_here'/VT_API_KEY = ''  # Set your API key here/" file-analyzer/app.py
echo "✅ VirusTotal API key set to empty for testing"
if docker ps > /dev/null 2>&1; then
    echo "Docker access: OK"
else
    echo "Docker access: FAILED - You may need to log out and back in for group changes to take effect"
fi

echo ""
echo "============================================"
echo "INSTALLATION COMPLETE!"
echo "============================================"
echo ""
echo "System is ready for SOC Tool deployment."
echo ""
echo "Next steps:"
echo "1. Run: docker-compose up --build -d"
echo "2. Optional: Update VirusTotal API key in file-analyzer/app.py"
echo ""
echo "If Docker group changes don't work, log out and back in, then run:"
echo "docker ps"
echo ""
echo "Access URLs after deployment:"
echo "https://$(hostname -I | awk '{print $1}'):3000 - Main Interface"
echo "http://$(hostname -I | awk '{print $1}'):8000/list - Clean Storage"
