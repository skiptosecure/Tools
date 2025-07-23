#!/bin/bash

# Trivy Security Dashboard - Rocky 9 Setup Script
# By Skip To Secure
# Run after: dnf update -y

set -e

echo "Trivy Security Dashboard Setup"
echo "=============================="
echo "Setting up on Rocky Linux 9..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "Please run this script as a regular user, not root!"
   exit 1
fi

# Update system first
print_status "Updating system packages..."
sudo dnf update -y

# Install system dependencies
print_status "Installing system dependencies..."
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y \
    python3 \
    python3-pip \
    python3-devel \
    curl \
    wget \
    git \
    unzip \
    firewalld

# Install Trivy
print_status "Installing Trivy security scanner..."
if ! command -v trivy &> /dev/null; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
    print_success "Trivy installed successfully"
else
    print_warning "Trivy already installed"
fi

# Verify Trivy installation
print_status "Verifying Trivy installation..."
trivy version

# Create application directory
APP_DIR="$HOME/trivy-security-dashboard"
if [ -d "$APP_DIR" ]; then
    print_warning "Directory $APP_DIR already exists. Backing up..."
    mv "$APP_DIR" "$APP_DIR.backup.$(date +%Y%m%d_%H%M%S)"
fi

print_status "Creating application directory: $APP_DIR"
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# Create Python virtual environment
print_status "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip

# Create requirements.txt inline (no download issues)
print_status "Creating requirements.txt..."
cat > requirements.txt << 'EOF'
Flask==3.0.0
Werkzeug==3.0.1
click>=8.0
importlib-metadata>=6.0
itsdangerous>=2.1.2
Jinja2>=3.1.2
MarkupSafe>=2.1.1
EOF

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install -r requirements.txt

# Download application files
print_status "Downloading application files from GitHub..."
curl -sSL https://raw.githubusercontent.com/skiptosecure/security-toolkits/main/Trivy-Scanner/app.py -o app.py
curl -sSL https://raw.githubusercontent.com/skiptosecure/security-toolkits/main/Trivy-Scanner/models.py -o models.py
curl -sSL https://raw.githubusercontent.com/skiptosecure/security-toolkits/main/Trivy-Scanner/scanner.py -o scanner.py

# Create static directory and download HTML
print_status "Creating static directory and downloading dashboard..."
mkdir -p static
curl -sSL https://raw.githubusercontent.com/skiptosecure/security-toolkits/main/Trivy-Scanner/dashboard.html -o static/dashboard.html

# Create setup directory and download database script
print_status "Setting up database components..."
mkdir -p setup
curl -sSL https://raw.githubusercontent.com/skiptosecure/security-toolkits/main/Trivy-Scanner/setup/create_database.py -o setup/create_database.py

print_success "Application files downloaded successfully"

# Create database
print_status "Creating database..."
python setup/create_database.py
print_success "Database created successfully"

# Set up firewall (open port 5001)
print_status "Configuring firewall..."
sudo firewall-cmd --permanent --add-port=5001/tcp
sudo firewall-cmd --reload
print_success "Firewall configured - port 5001 open"

# Create systemd service (optional)
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/trivy-dashboard.service > /dev/null << EOF
[Unit]
Description=Trivy Security Dashboard
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin
ExecStart=$APP_DIR/venv/bin/python app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
print_success "Systemd service created"

# Get system IP
SYSTEM_IP=$(hostname -I | awk '{print $1}')

# Final instructions
echo ""
echo "Setup Complete!"
echo "==============="
echo ""
echo "Application installed in: $APP_DIR"
echo "Access URL: http://$SYSTEM_IP:5001"
echo "Local URL: http://localhost:5001"
echo ""
echo "To start the dashboard:"
echo "   cd $APP_DIR"
echo "   source venv/bin/activate"
echo "   python app.py"
echo ""
echo "To start as a service:"
echo "   sudo systemctl enable trivy-dashboard"
echo "   sudo systemctl start trivy-dashboard"
echo ""
echo "Database and all files are ready!"
echo "Test with: curl http://localhost:5001"
echo ""
print_success "Ready to use! Everything is set up automatically."
