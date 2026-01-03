#!/bin/bash
# ============================================================================
# VectorAI MCP Server - Entrypoint Script
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║  ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗  █████╗ ██╗║"
echo "║  ██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗██║║"
echo "║  ██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝███████║██║║"
echo "║  ╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗██╔══██║██║║"
echo "║   ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██║║"
echo "║    ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝║"
echo "║                                                               ║"
echo "║            MCP Server v6.0 - Dockerized                       ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to log messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a tool exists
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 (not found)"
        return 1
    fi
}

# Function to verify tools
verify_tools() {
    log_info "Verifying installed security tools..."
    
    echo ""
    echo "Network Tools:"
    check_tool "nmap" || true
    check_tool "masscan" || true
    check_tool "rustscan" || true
    check_tool "amass" || true
    
    echo ""
    echo "Web Tools:"
    check_tool "gobuster" || true
    check_tool "ffuf" || true
    check_tool "nuclei" || true
    check_tool "sqlmap" || true
    check_tool "nikto" || true
    
    echo ""
    echo "Password Tools:"
    check_tool "hydra" || true
    check_tool "john" || true
    check_tool "hashcat" || true
    
    echo ""
    echo "Binary Analysis:"
    check_tool "gdb" || true
    check_tool "radare2" || true
    check_tool "binwalk" || true
    
    echo ""
    echo "Cloud Security:"
    check_tool "aws" || true
    check_tool "trivy" || true
    
    echo ""
}

# Function to start the server
start_server() {
    log_info "Starting VectorAI MCP Server..."
    log_info "Host: ${VECTORAI_HOST:-0.0.0.0}"
    log_info "Port: ${VECTORAI_PORT:-8888}"
    
    cd /app/vectorai
    
    # Activate virtual environment
    source /app/venv/bin/activate
    
    # Build command arguments
    CMD_ARGS=""
    
    if [ "${VECTORAI_DEBUG:-false}" = "true" ]; then
        log_info "Debug mode: ENABLED"
        CMD_ARGS="$CMD_ARGS --debug"
    fi
    
    CMD_ARGS="$CMD_ARGS --port ${VECTORAI_PORT:-8888}"
    
    # Start the server
    log_info "Executing: python3 vectorai_server.py $CMD_ARGS"
    echo ""
    
    exec python3 vectorai_server.py $CMD_ARGS
}

# Function to run health check
health_check() {
    log_info "Running health check..."
    
    # Check server health
    if curl -sf "http://localhost:${VECTORAI_PORT:-8888}/health" > /dev/null 2>&1; then
        log_info "Server is healthy!"
        exit 0
    else
        log_error "Server health check failed!"
        exit 1
    fi
}

# Function to run shell
run_shell() {
    log_info "Starting shell..."
    source /app/venv/bin/activate
    exec /bin/bash
}

# Main entrypoint logic
case "${1:-server}" in
    server)
        verify_tools
        start_server
        ;;
    health)
        health_check
        ;;
    shell)
        run_shell
        ;;
    verify)
        verify_tools
        ;;
    *)
        # If command doesn't match, pass it through
        exec "$@"
        ;;
esac
