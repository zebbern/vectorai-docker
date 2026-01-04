## VectorAI MCP Server

**AI-Powered Penetration Testing Framework** with 70+ pre-installed security tools.

[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fzebbern%2Fvectorai-blue)](https://ghcr.io/zebbern/vectorai)
[![Tools](https://img.shields.io/badge/Tools-70%2B-green)](https://github.com/zebbern/vectorai-docker)

---

## Quick Start

```bash
# Pull and run
docker pull ghcr.io/zebbern/vectorai:latest
docker run -d --name vectorai -p 8888:8888 -p 8080:8080 ghcr.io/zebbern/vectorai:latest

# Verify it's running:
curl http://localhost:8888/health
```

## 🛑 Stop / Manage Containers

```bash
# Check running containers
docker ps | grep vectorai

# Check all containers (including stopped)
docker ps -a | grep vectorai
```

### Stop VectorAI
```bash
# Stop the container
docker stop vectorai

# Stop and remove the container
docker stop vectorai && docker rm vectorai
```

### Restart VectorAI
```bash
docker restart vectorai
```

### View Logs
```bash
# Follow logs in real-time
docker logs -f vectorai

# Last 100 lines
docker logs --tail 100 vectorai
```

### Enter Container Shell
```bash
docker exec -it vectorai bash
```

---

## Alternative: Docker Compose

### Option A: Use Pre-built Image (Recommended)
```bash
git clone https://github.com/zebbern/vectorai-docker.git
cd vectorai-docker
docker compose -f docker-compose.pull.yml up -d
```

### Option B: Build from Source
```bash
git clone https://github.com/zebbern/vectorai-docker.git
cd vectorai-docker
docker compose up -d --build  # Takes 15-30 minutes
```

### Docker Compose Commands
```bash
# Start
docker compose up -d

# Stop
docker compose down

# Stop and remove volumes
docker compose down -v

# View status
docker compose ps

# View logs
docker compose logs -f
```

---

## VS Code Integration

### Configure MCP Client

Create `.vscode/mcp.json` in your project:

```json
{
    "servers": {
        "vectorai": {
            "type": "stdio",
            "command": "python",
            "args": [
                "vectorai_mcp_client.py",
                "--server",
                "http://localhost:8888"
            ]
        }
    }
}
```

### Install Python Dependencies
```bash
pip install requests fastmcp
```

---

## Included Tools (70+)

| Category | Tools |
|----------|-------|
| **Network** | nmap, masscan, rustscan, amass, subfinder, dnsenum, theharvester |
| **Web** | gobuster, ffuf, nuclei, nikto, sqlmap, wpscan, httpx, OWASP ZAP |
| **Password** | hydra, john, hashcat, medusa, crackmapexec, evil-winrm |
| **Binary** | gdb, radare2, binwalk, ghidra, pwntools, ropper, ROPgadget |
| **Cloud** | prowler, scout-suite, trivy, checkov, aws-cli |
| **Forensics** | volatility3, foremost, steghide, exiftool |
| **Exploit** | Metasploit Framework, searchsploit |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VECTORAI_PORT` | 8888 | API server port |
| `VECTORAI_DEBUG` | false | Debug mode |

### Custom Configuration
```bash
# Copy example config
cp .env.example .env

# Edit as needed
nano .env
```

---

## Health Check & API

### Health Endpoint
```bash
curl http://localhost:8888/health
```

### Test Command Execution
```bash
curl -X POST http://localhost:8888/api/command \
  -H "Content-Type: application/json" \
  -d '{"command": "nmap --version"}'
```

---

## Troubleshooting

### Port Already in Use
```bash
# Check what's using port 8888
netstat -ano | findstr 8888  # Windows
lsof -i :8888                # Linux/Mac

# Use different port
docker run -d --name vectorai -p 9999:8888 ghcr.io/zebbern/vectorai:latest
```

### Container Won't Start
```bash
# Check logs
docker logs vectorai

# Remove and recreate
docker rm -f vectorai
docker run -d --name vectorai -p 8888:8888 -p 8080:8080 ghcr.io/zebbern/vectorai:latest
```

### Clean Everything
```bash
# Stop all VectorAI containers
docker stop vectorai 2>/dev/null
docker rm vectorai 2>/dev/null

# Remove image (to re-download)
docker rmi ghcr.io/zebbern/vectorai:latest
```

