# ============================================================================
# VectorAI MCP Server - Docker Container (Optimized)
# Version: 6.1 (Optimized Build)
# Base: Kali Linux (includes most security tools pre-installed)
# 
# Optimization Summary:
# - Consolidated apt-get operations (7 → 2 RUN commands)
# - Consolidated pip installs with --no-cache-dir
# - Alphabetically sorted packages for maintainability
# - Cleaned Go cache after installations
# - Removed temp files in same layer
# - Added VOLUME for persistent session data
# - Added build ARGs for version pinning
# ============================================================================

FROM kalilinux/kali-rolling:latest

# Build arguments for version pinning (easy to update)
ARG KUBE_BENCH_VERSION=0.7.0
ARG PYTHON_VENV_PATH=/app/venv

LABEL maintainer="VectorAI Docker Setup"
LABEL description="VectorAI MCP Server with 70+ security tools"
LABEL version="6.1-optimized"

# ============================================================================
# Environment Variables (consolidated)
# ============================================================================

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Python configuration
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Go configuration
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin:/usr/local/go/bin

# Chrome/Chromium configuration
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

# ZAP configuration
ENV ZAP_PORT=8080

# VectorAI configuration
ENV PATH="${PYTHON_VENV_PATH}/bin:$PATH"
ENV VECTORAI_HOME="/app/vectorai"
ENV VECTORAI_PORT=8888
ENV VECTORAI_HOST=0.0.0.0

# ============================================================================
# STAGE 1: System Packages (ALL apt-get consolidated into ONE command)
# 
# Categories included:
# - Core utilities & build tools
# - Python runtime
# - Network & reconnaissance tools
# - Web application security tools
# - Password & authentication tools
# - Binary analysis & reverse engineering
# - Forensics & CTF tools
# - OSINT tools
# - Cloud tools prerequisites
# - Browser for automation
# - Metasploit Framework
# ============================================================================

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    # ===== Core Utilities (alphabetically sorted) =====
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    golang \
    jq \
    lsb-release \
    nano \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    software-properties-common \
    unzip \
    vim \
    wget \
    zip \
    # ===== Network & Reconnaissance (alphabetically sorted) =====
    amass \
    arp-scan \
    dnsenum \
    dnsutils \
    enum4linux-ng \
    fierce \
    masscan \
    nbtscan \
    netcat-openbsd \
    netexec \
    nmap \
    proxychains4 \
    responder \
    socat \
    subfinder \
    tcpdump \
    theharvester \
    tor \
    tshark \
    # ===== Web Application Security (alphabetically sorted) =====
    arjun \
    dirb \
    dirsearch \
    feroxbuster \
    ffuf \
    gobuster \
    hakrawler \
    httpx-toolkit \
    nikto \
    nuclei \
    sqlmap \
    wafw00f \
    whatweb \
    wpscan \
    # ===== Password & Authentication (alphabetically sorted) =====
    crackmapexec \
    evil-winrm \
    hash-identifier \
    hashcat \
    hashid \
    hydra \
    john \
    medusa \
    patator \
    # rsatool \
    stegcracker \
    # yafu \
    # ===== SMB & Windows (alphabetically sorted) =====
    samba-common-bin \
    smbclient \
    smbmap \
    # ===== Binary Analysis & Reverse Engineering (alphabetically sorted) =====
    binwalk \
    checksec \
    gdb \
    ghidra \
    jadx \
    jd-gui \
    ltrace \
    radare2 \
    ropper \
    strace \
    # ===== Forensics & CTF (alphabetically sorted) =====
    autopsy \
    bulk-extractor \
    dc3dd \
    exiftool \
    foremost \
    gddrescue \
    p7zip-full \
    scalpel \
    sleuthkit \
    steghide \
    testdisk \
    unrar \
    upx-ucl \
    zbar-tools \
    # ===== Mobile Security (alphabetically sorted) =====
    adb \
    apktool \
    dex2jar \
    # ===== OSINT (alphabetically sorted) =====
    dnsrecon \
    maltego \
    recon-ng \
    sherlock \
    spiderfoot \
    sublist3r \
    whois \
    # ===== Cloud & Infrastructure (alphabetically sorted) =====
    # ansible \
    # docker.io \
    # kubectl \
    # terraform \
    # ===== SSL/TLS & Security (alphabetically sorted) =====
    sslscan \
    testssl.sh \
    # ===== Browser & Automation (alphabetically sorted) =====
    chromium \
    chromium-driver \
    # ===== ZAP =====
    zaproxy \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# ============================================================================
# STAGE 2: Metasploit Framework (separate due to size ~2GB)
# Includes searchsploit from exploitdb
# ============================================================================

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    exploitdb \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# ============================================================================
# STAGE 3: Go-based Security Tools
# Clean Go cache after installations to reduce image size
# ============================================================================

RUN go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true && \
    go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install github.com/RustScan/RustScan@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/anew@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/qsreplace@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/assetfinder@latest 2>/dev/null || true && \
    # Clean Go cache to reduce image size (saves ~500MB+)
    go clean -cache -modcache -testcache && \
    rm -rf /root/.cache/go-build /tmp/go-*

# ============================================================================
# STAGE 4: Cloud Security Tools (binaries)
# ============================================================================

RUN \
    # Trivy - Container vulnerability scanner
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true && \
    # AWS CLI v2 - Clean up in same layer
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip && \
    unzip -q /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install && \
    rm -rf /tmp/awscliv2.zip /tmp/aws && \
    # Kube-bench - Kubernetes security benchmark
    curl -fsSL "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_amd64.tar.gz" -o /tmp/kube-bench.tar.gz && \
    tar -xzf /tmp/kube-bench.tar.gz -C /tmp && \
    mv /tmp/kube-bench /usr/local/bin/ && \
    rm -rf /tmp/kube-bench.tar.gz /tmp/cfg 2>/dev/null || true

# ============================================================================
# STAGE 5: Python Virtual Environment & ALL Dependencies
# Using --no-cache-dir to avoid storing pip cache (saves ~200MB+)
# ============================================================================

WORKDIR /app

# Create directories
RUN mkdir -p /app/vectorai /app/output /app/logs /app/cache /app/scans /tmp/vectorai

# Copy application files
COPY vectorai_server.py /app/vectorai/
COPY vectorai_mcp.py /app/vectorai/

WORKDIR /app/vectorai

# Create venv and install ALL Python packages in a single consolidated command
RUN python3 -m venv ${PYTHON_VENV_PATH} && \
    ${PYTHON_VENV_PATH}/bin/pip install --no-cache-dir --upgrade pip wheel setuptools && \
    # ===== Core Application Dependencies =====
    ${PYTHON_VENV_PATH}/bin/pip install --no-cache-dir \
        aiohttp>=3.8.0 \
        bcrypt==4.0.1 \
        beautifulsoup4>=4.12.0 \
        fastmcp>=0.2.0 \
        flask>=2.3.0 \
        mitmproxy>=9.0.0 \
        psutil>=5.9.0 \
        requests>=2.31.0 \
        selenium>=4.15.0 \
        shodan \
        volatility3 \
        webdriver-manager>=4.0.0 \
    && \
    # ===== Cloud Security Tools =====
    ${PYTHON_VENV_PATH}/bin/pip install --no-cache-dir \
        apkleaks \
        censys \
        checkov \
        frida-tools \
        objection \
        prowler \
        scoutsuite \
    2>/dev/null || true && \
    # ===== Binary Analysis (may fail on some architectures) =====
    ${PYTHON_VENV_PATH}/bin/pip install --no-cache-dir \
        capstone \
        keystone-engine \
        one_gadget \
        pwntools>=4.10.0 \
        ROPGadget \
        ropper \
        unicorn \
    2>/dev/null || true && \
    # ===== Heavy packages (separate for better error handling) =====
    ${PYTHON_VENV_PATH}/bin/pip install --no-cache-dir angr>=9.2.0 2>/dev/null || true && \
    # Clean up any remaining pip cache
    rm -rf /root/.cache/pip /tmp/pip-*

# ============================================================================
# STAGE 6: Final Configuration
# ============================================================================

# Set permissions
RUN chmod -R 755 /app

# Declare volume for persistent session data
VOLUME ["/app/scans"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${VECTORAI_PORT}/health || exit 1

# Expose ports
EXPOSE 8888 8080

# Copy and configure entrypoint
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["server"]
