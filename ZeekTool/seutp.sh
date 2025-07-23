#!/bin/bash

# Zeek Analysis Tools Installer
# Installs podman, Python, and sets up Zeek container for network analysis
# By Skip to Secure

set -e  # Exit on any error

echo "======================================"
echo "Zeek Analysis Tools Installer"
echo "by Skip to Secure"
echo "======================================"

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        OS=Debian
        VER=$(cat /etc/debian_version)
    elif [ -f /etc/SuSe-release ]; then
        OS=openSUSE
    elif [ -f /etc/redhat-release ]; then
        OS=RedHat
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        echo "Please do not run this script as root. It will use sudo when needed."
        exit 1
    fi
}

# Install packages for different distributions
install_packages() {
    echo "Detected OS: $OS $VER"
    
    case "$OS" in
        "Fedora Linux"|"Fedora")
            echo "Installing packages for Fedora..."
            sudo dnf update -y
            sudo dnf install -y podman python3 python3-pip git curl wget
            ;;
        "CentOS Linux"|"CentOS"|"Red Hat Enterprise Linux"|"Rocky Linux"|"AlmaLinux")
            echo "Installing packages for RHEL/CentOS..."
            sudo dnf update -y || sudo yum update -y
            sudo dnf install -y podman python3 python3-pip git curl wget || \
            sudo yum install -y podman python3 python3-pip git curl wget
            ;;
        "Ubuntu"|"Debian GNU/Linux"|"Debian")
            echo "Installing packages for Ubuntu/Debian..."
            sudo apt update
            sudo apt install -y podman python3 python3-pip git curl wget
            ;;
        "openSUSE"*|"SUSE"*)
            echo "Installing packages for openSUSE..."
            sudo zypper refresh
            sudo zypper install -y podman python3 python3-pip git curl wget
            ;;
        "Arch Linux"|"Manjaro"*)
            echo "Installing packages for Arch/Manjaro..."
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm podman python python-pip git curl wget
            ;;
        *)
            echo "Unsupported distribution: $OS"
            echo "Please install the following packages manually:"
            echo "- podman"
            echo "- python3"
            echo "- python3-pip"
            echo "- git"
            echo "- curl"
            echo "- wget"
            exit 1
            ;;
    esac
}

# Configure podman for rootless operation
configure_podman() {
    echo "Configuring podman for rootless operation..."
    
    # Start and enable podman socket (if systemd is available)
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user enable --now podman.socket 2>/dev/null || true
    fi
    
    # Configure subuid/subgid if not already done
    if ! grep -q "^$(whoami):" /etc/subuid 2>/dev/null; then
        echo "Setting up user namespaces..."
        echo "$(whoami):100000:65536" | sudo tee -a /etc/subuid
        echo "$(whoami):100000:65536" | sudo tee -a /etc/subgid
        podman system migrate 2>/dev/null || true
    fi
}

# Check for SELinux
check_selinux() {
    if command -v getenforce >/dev/null 2>&1; then
        if [ "$(getenforce)" = "Enforcing" ]; then
            echo "WARNING: SELinux is currently enforcing"
            echo "This may cause issues with container volume mounts"
            SELINUX_WARNING=true
        fi
    fi
}

# Download and test Zeek container
setup_zeek_container() {
    echo "Downloading Zeek container image..."
    podman pull docker.io/zeek/zeek:latest
    
    echo "Testing Zeek container..."
    if podman run --rm docker.io/zeek/zeek:latest zeek --version; then
        echo "Zeek container is working properly!"
    else
        echo "Error: Zeek container test failed"
        exit 1
    fi
}

# Download the Python tools
download_tools() {
    echo "Downloading zeekapp.py and zeekdash.py..."
    
    # Create zeek-tools directory if it doesn't exist
    mkdir -p ~/zeek-tools
    cd ~/zeek-tools
    
    # Download zeekapp.py
    if curl -L -o zeekapp.py "https://raw.githubusercontent.com/skiptosecure/Tools/main/ZeekTool/zeekapp.py"; then
        echo "Downloaded zeekapp.py"
        chmod +x zeekapp.py
    else
        echo "Error downloading zeekapp.py"
        exit 1
    fi
    
    # Download zeekdash.py
    if curl -L -o zeekdash.py "https://raw.githubusercontent.com/skiptosecure/Tools/main/ZeekTool/zeekdash.py"; then
        echo "Downloaded zeekdash.py"
        chmod +x zeekdash.py
    else
        echo "Error downloading zeekdash.py"
        exit 1
    fi
    
    echo "Tools downloaded successfully to ~/zeek-tools/"
}

# Verify installation
verify_installation() {
    echo "Verifying installation..."
    
    # Check podman
    if ! command -v podman >/dev/null 2>&1; then
        echo "Error: podman not found"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: python3 not found"
        exit 1
    fi
    
    # Check if Zeek container is available
    if ! podman images | grep -q zeek/zeek; then
        echo "Error: Zeek container not found"
        exit 1
    fi
    
    # Check if Python tools exist
    if [ ! -f ~/zeek-tools/zeekapp.py ] || [ ! -f ~/zeek-tools/zeekdash.py ]; then
        echo "Error: Python tools not found"
        exit 1
    fi
    
    echo "All components verified successfully!"
}

# Main installation flow
main() {
    SELINUX_WARNING=false
    
    check_root
    detect_distro
    
    echo "Installing required packages..."
    install_packages
    
    echo "Configuring podman..."
    configure_podman
    
    echo "Checking SELinux..."
    check_selinux
    
    echo "Setting up Zeek container..."
    setup_zeek_container
    
    echo "Downloading Python tools..."
    download_tools
    
    echo "Verifying installation..."
    verify_installation
    
    echo ""
    echo "======================================"
    echo "Installation Complete!"
    echo "======================================"
    echo ""
    echo "Ready to use!"
    echo "cd ~/zeek-tools"
    echo "python3 zeekapp.py <your_pcap_file>"
    echo ""
    
    if [ "$SELINUX_WARNING" = true ]; then
        echo "IMPORTANT SELinux Notice:"
        echo "========================="
        echo "SELinux is currently enforcing and may block container operations."
        echo "If you experience permission errors, you can:"
        echo "  sudo setenforce 0                    # Temporary disable"
        echo "  # OR edit /etc/selinux/config and set SELINUX=permissive"
        echo ""
    fi
    
    echo "The tools will:"
    echo "- Analyze your PCAP with Zeek"
    echo "- Generate security analysis reports"
    echo "- Create beautiful HTML dashboards"
    echo ""
    echo "Enjoy your network security analysis!"
    echo "- Skip to Secure"
}

# Run main function
main "$@"
