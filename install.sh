#!/bin/bash

echo "========================================"
echo "Advanced SQL Injection Scanner Setup"
echo "========================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check if Python is installed
print_status "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    print_error "Python is not installed or not in PATH"
    echo "Please install Python 3.7+ from https://python.org"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)
print_success "Python $PYTHON_VERSION found!"
echo

# Check if pip is available
print_status "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    print_error "pip is not installed"
    echo "Please install pip first"
    exit 1
fi

print_success "pip found!"
echo

# Install Python dependencies
print_status "Installing Python dependencies..."
$PIP_CMD install -r requirements.txt

if [ $? -eq 0 ]; then
    print_success "Dependencies installed successfully!"
else
    print_error "Failed to install dependencies"
    exit 1
fi
echo

# Optional Playwright installation
print_status "Playwright installation (optional for JavaScript support)"
read -p "Install Playwright browsers? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Installing Playwright browsers..."
    $PYTHON_CMD -m playwright install
    if [ $? -eq 0 ]; then
        print_success "Playwright browsers installed!"
    else
        print_warning "Playwright installation failed, continuing without it"
    fi
else
    print_status "Skipping Playwright installation"
fi
echo

# Create necessary directories
print_status "Creating directories..."
mkdir -p results
mkdir -p logs
print_success "Directories created!"
echo

# Set executable permissions
print_status "Setting executable permissions..."
chmod +x main.py
chmod +x examples/*.py
chmod +x install.sh
print_success "Permissions set!"
echo

# Installation complete
echo "========================================"
print_success "Installation completed successfully!"
echo "========================================"
echo
echo "Quick start:"
echo "  $PYTHON_CMD main.py -u \"http://example.com/page.php?id=1\""
echo
echo "For help:"
echo "  $PYTHON_CMD main.py --help"
echo
echo "Examples:"
echo "  $PYTHON_CMD examples/basic_scan.py"
echo "  $PYTHON_CMD examples/advanced_scan.py"
echo
echo "Configuration:"
echo "  Edit config/scanner_config.json for advanced settings"
echo "  Add custom payloads to payloads/custom_payloads.txt"
echo
echo "Happy hunting! 🎯"
