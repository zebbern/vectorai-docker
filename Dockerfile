# ============================================================================
# VectorAI MCP Server - Docker Container
# Version: 6.0 (Dockerized)
# Base: Kali Linux (includes most security tools pre-installed)
# ============================================================================

FROM kalilinux/kali-rolling:latest

LABEL maintainer="VectorAI Docker Setup"
LABEL description="VectorAI MCP Server with 70+ security tools"
LABEL version="6.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Set Python environment
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ============================================================================
# STAGE 1: System Updates and Base Dependencies
# ============================================================================

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    # Core utilities
    curl \
    wget \
    git \
    vim \
    nano \
    unzip \
    zip \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    build-essential \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# STAGE 2: Install Kali Security Tools (Available via apt)
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network & Reconnaissance
    nmap \
    masscan \
    amass \
    subfinder \
    fierce \
    dnsenum \
    theharvester \
    responder \
    netexec \
    enum4linux-ng \
    # Web Application Security
    gobuster \
    feroxbuster \
    ffuf \
    dirb \
    dirsearch \
    nuclei \
    nikto \
    sqlmap \
    wpscan \
    arjun \
    httpx-toolkit \
    hakrawler \
    wafw00f \
    whatweb \
    # Password & Authentication
    hydra \
    john \
    hashcat \
    medusa \
    patator \
    crackmapexec \
    evil-winrm \
    hash-identifier \
    # Binary Analysis & Reverse Engineering
    gdb \
    radare2 \
    binwalk \
    ghidra \
    checksec \
    ropper \
    # Forensics & CTF tools
    foremost \
    steghide \
    exiftool \
    testdisk \
    sleuthkit \
    # OSINT tools
    sherlock \
    recon-ng \
    spiderfoot \
    # Additional utilities
    sslscan \
    testssl.sh \
    jq \
    dnsutils \
    netcat-openbsd \
    socat \
    proxychains4 \
    tor \
    # Network capture & analysis
    tcpdump \
    tshark \
    arp-scan \
    nbtscan \
    smbclient \
    smbmap \
    samba-common-bin \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# STAGE 3: Install Metasploit Framework
# ============================================================================

# Install Metasploit (adds ~2GB to image but provides msfconsole, msfvenom, searchsploit)
RUN apt-get update && apt-get install -y --no-install-recommends \
    metasploit-framework \
    exploitdb \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# STAGE 4: Install Go and Go-based Security Tools
# ============================================================================

# Install Go tools (many security tools are Go-based)
RUN apt-get update && apt-get install -y golang && \
    rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin:/usr/local/go/bin

# Install Go-based security tools (not available via apt)
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true && \
    go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/anew@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/qsreplace@latest 2>/dev/null || true && \
    go install github.com/RustScan/RustScan@latest 2>/dev/null || true

# ============================================================================
# STAGE 5: Install Chrome/Chromium for Browser Agent
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

# ============================================================================
# STAGE 6: Install OWASP ZAP (Headless with API)
# ============================================================================

# Install ZAP dependencies and ZAP itself
RUN apt-get update && apt-get install -y --no-install-recommends \
    zaproxy \
    && rm -rf /var/lib/apt/lists/*

# ZAP API will be available on port 8080
ENV ZAP_PORT=8080

# ============================================================================
# STAGE 7: Copy VectorAI Server and Install Python Dependencies
# ============================================================================

WORKDIR /app

# Create vectorai directory and copy server files
RUN mkdir -p /app/vectorai
COPY vectorai_server.py /app/vectorai/
COPY vectorai_mcp.py /app/vectorai/

WORKDIR /app/vectorai

# Create virtual environment and install Python dependencies
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install wheel setuptools

# Install Python requirements
RUN /app/venv/bin/pip install \
    flask>=2.3.0 \
    requests>=2.31.0 \
    psutil>=5.9.0 \
    fastmcp>=0.2.0 \
    beautifulsoup4>=4.12.0 \
    selenium>=4.15.0 \
    webdriver-manager>=4.0.0 \
    aiohttp>=3.8.0 \
    mitmproxy>=9.0.0 \
    bcrypt==4.0.1 \
    shodan \
    volatility3

# Install pwntools and angr (optional, may fail on some architectures)
RUN /app/venv/bin/pip install pwntools>=4.10.0 || true
RUN /app/venv/bin/pip install angr>=9.2.0 || true

# Install additional Python security tools
RUN /app/venv/bin/pip install \
    ROPGadget \
    one_gadget \
    capstone \
    keystone-engine \
    unicorn \
    ropper \
    || true

# ============================================================================
# STAGE 8: Install Cloud Security Tools
# ============================================================================

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || true

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip -q awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws

# Install Prowler
RUN /app/venv/bin/pip install prowler || true

# Install Scout Suite
RUN /app/venv/bin/pip install scoutsuite || true

# Install Checkov
RUN /app/venv/bin/pip install checkov || true

# Install kube-bench (download binary)
RUN curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.0/kube-bench_0.7.0_linux_amd64.tar.gz -o kube-bench.tar.gz && \
    tar -xzf kube-bench.tar.gz && \
    mv kube-bench /usr/local/bin/ && \
    rm kube-bench.tar.gz || true

# ============================================================================
# STAGE 9: Create Directories and Set Permissions
# ============================================================================

# Create output directories
RUN mkdir -p /app/output /app/logs /app/cache /tmp/vectorai

# Set proper permissions
RUN chmod -R 755 /app

# ============================================================================
# STAGE 10: Configure Environment
# ============================================================================

# Set PATH to include virtual environment
ENV PATH="/app/venv/bin:$PATH"
ENV VECTORAI_HOME="/app/vectorai"

# Default port for VectorAI server
ENV VECTORAI_PORT=8888
ENV VECTORAI_HOST=0.0.0.0

# ============================================================================
# STAGE 11: Healthcheck and Entrypoint
# ============================================================================

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${VECTORAI_PORT}/health || exit 1

# Expose the VectorAI server port and ZAP API port
EXPOSE 8888
EXPOSE 8080

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command
CMD ["server"]
