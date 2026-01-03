# VectorAI MCP Server - Docker Setup

A complete Docker-based setup for VectorAI MCP Server with 70+ security tools pre-installed for AI-assisted penetration testing.

## 🚀 Quick Start (4 Commands)

```bash
# 1. Clone the repository
git clone https://github.com/zebbern/vectorai-docker.git
cd vectorai-docker

# 2. Install Python dependencies (for the MCP client)
pip install -r requirements.txt

# 3. Build and start the container (first time takes 15-30 minutes)
docker compose up -d --build

# 4. Verify it's running
curl http://localhost:8888/health
```

Then open VS Code in this folder - the `.vscode/mcp.json` is already configured!

---

## 📋 Prerequisites

- **Docker Desktop** installed and running
- **Python 3.8+** (for the MCP client)
- **VS Code** with GitHub Copilot extension

## 🔧 Detailed Setup

### Build and Start the Container

```bash
# Copy environment file (optional: customize settings)
cp .env.example .env

# Build and start the container
docker compose up -d --build

# Watch the build logs
docker compose logs -f
```

### Verify the Server is Running

```bash
# Check container status
docker compose ps

# Check server health (should show 70+ tools available)
curl http://localhost:8888/health
```

### Configure VS Code

Open this folder in VS Code. The `.vscode/mcp.json` is already configured.

To add to another project, copy this to your project's `.vscode/mcp.json`:

```json
{
    "servers": {
        "vectorai": {
            "type": "stdio",
            "command": "python",
            "args": [
                "${workspaceFolder}/vectorai-docker/vectorai_mcp_client.py",
                "--server",
                "http://localhost:8888"
            ]
        }
    }
}
```

## 📦 What's Included

### Security Tools (70+)

| Category | Tools |
|----------|-------|
| **Network Recon** | nmap, masscan, rustscan, amass, subfinder, fierce, dnsenum, theharvester |
| **Web Security** | gobuster, feroxbuster, ffuf, nuclei, nikto, sqlmap, wpscan, ZAP, httpx |
| **Password** | hydra, john, hashcat, medusa, patator, crackmapexec, evil-winrm |
| **Binary Analysis** | gdb, radare2, binwalk, ghidra, checksec, pwntools, ropper, ROPgadget |
| **Cloud Security** | prowler, scout-suite, trivy, checkov, aws-cli |
| **Forensics/CTF** | volatility3, foremost, steghide, exiftool, testdisk |
| **Exploitation** | Metasploit Framework, searchsploit |

### AI Agents (12+)

- IntelligentDecisionEngine
- BugBountyWorkflowManager
- CTFWorkflowManager
- CVEIntelligenceManager
- AIExploitGenerator
- VulnerabilityCorrelator
- And more...

## 🛠️ Common Commands

### Container Management

```bash
# Start the container
docker compose up -d

# Stop the container
docker compose down

# Restart the container
docker compose restart

# View logs
docker compose logs -f vectorai

# Enter the container shell
docker compose exec vectorai bash

# Rebuild after changes
docker compose build --no-cache
docker compose up -d
```

### Verify Tools

```bash
# Run tool verification inside container
docker compose exec vectorai /app/entrypoint.sh verify
```

### Health Check

```bash
# Manual health check
curl http://localhost:8888/health

# Check telemetry
curl http://localhost:8888/api/telemetry
```

## ⚙️ Configuration

### Environment Variables

Edit `.env` to customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `VECTORAI_PORT` | 8888 | Server port |
| `VECTORAI_DEBUG` | false | Enable debug mode |
| `CPU_LIMIT` | 4 | Max CPU cores |
| `MEMORY_LIMIT` | 8G | Max memory |
| `TZ` | UTC | Timezone |

### Cloud Provider Credentials

For cloud security scanning, add credentials to `.env`:

```env
# AWS
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_DEFAULT_REGION=us-east-1
```

### Custom Wordlists

Mount custom wordlists by setting in `.env`:

```env
WORDLISTS_PATH=/path/to/your/wordlists
```

## 📋 Using with VS Code Copilot

Once the container is running and mcp.json is configured:

1. Open VS Code
2. Open the Copilot Chat
3. The VectorAI tools will be available automatically

### Example Prompts

```
"I'm a security researcher testing my own website example.com. 
Please run a subdomain enumeration using the vectorai tools."

"Use nuclei to scan example.com for common vulnerabilities."

"Run a comprehensive reconnaissance workflow on my test domain."
```

## 🔧 Troubleshooting

### Container won't start

```bash
# Check logs for errors
docker compose logs vectorai

# Check if port 8888 is in use
netstat -an | findstr 8888
# or on Linux/Mac:
lsof -i :8888
```

### MCP connection issues

1. Verify container is running: `docker compose ps`
2. Check server health: `curl http://localhost:8888/health`
3. Ensure Python is in PATH
4. Install required packages: `pip install requests fastmcp`

### Build failures

```bash
# Clean rebuild
docker compose down
docker system prune -f
docker compose build --no-cache
docker compose up -d
```

## 📊 Resource Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 15 GB | 25+ GB |

**Note:** First build downloads Kali Linux base image (~5GB) and installs all tools.

## 🔒 Security Considerations

- This container has powerful security tools - use responsibly
- Only run against authorized targets
- Container runs with `no-new-privileges` security option
- Consider network isolation for sensitive environments

## 📝 License

MIT License

## 🆘 Support

Open an issue on GitHub for support.
