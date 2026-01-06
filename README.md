# VectorAI - Advanced AI Penetration Testing Framework

[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fzebbern%2Fvectorai-blue)](https://ghcr.io/zebbern/vectorai)
[![Tools](https://img.shields.io/badge/Tools-70%2B-green)](https://github.com/zebbern/vectorai-docker)
[![Version](https://img.shields.io/badge/Version-6.1-orange)](https://github.com/zebbern/vectorai-docker)
[![Status](https://img.shields.io/badge/Status-Refactored%20%26%20Modular-brightgreen)]()

VectorAI is a next-generation, **AI-powered penetration testing framework** designed for Bug Bounty hunters, CTF players, and Red Teams. It goes beyond simple automation by using an intelligent decision engine to analyze results in real-time and adapt its attack strategy.

---

## 🚀 Key Features

*   **🧠 Intelligent Decision Engine**: Unlike linear scripts, VectorAI analyzes tool output to decide the next best move.
*   **🏗️ Modular Architecture**: 
    *   **Interface**: A lightweight Flask server (`vectorai_server.py`) handling APIs.
    *   **Core**: A robust logic engine (`vectorai_app/`) managing workflows, tools, and intelligence.
*   **🛠️ 70+ Integrated Tools**: Seamlessly orchestrates industry-standard tools like Nmap, Nuclei, SQLMap, Metasploit, and more.
*   **🔄 Automated Workflows**: Pre-built playbooks for:
    *   **Bug Bounties** (Recon -> Vulnerability Scanning)
    *   **CTF Challenges** (Jeopardy & Attack-Defense)
    *   **Red Teaming** (Full kill-chain simulation)
*   **📊 Comprehensive Reporting**: Generates detailed JSON and Markdown reports with findings and remediation steps.

---

## 📂 Project Structure

The project has been refactored for stability and extensibility:

```text
hexstrike-docker/
├── vectorai_server.py    # [ENTRY POINT] API Gateway & Web Server
├── vectorai_app/         # [CORE LOGIC]
│   ├── core/             # AI Engine, Recon, & Intelligence
│   ├── workflows/        # Automated Playbooks (Bug Bounty, CTF)
│   ├── tools/            # Tool Wrappers & Managers
│   └── tests/            # Unit & Integration Tests
├── requirements.txt      # Python Dependencies
└── USERGUIDE.md          # Detailed Usage Instructions
```

---

## ⚡ Quick Start

### Option 1: Local Python (Recommended for Dev)

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Start the Server**:
    ```bash
    python vectorai_server.py
    ```
    *   Server runs on `http://localhost:8888`

3.  **Verify**:
    ```bash
    curl http://localhost:8888/health
    ```

### Option 2: Docker

```bash
docker pull ghcr.io/zebbern/vectorai:latest
docker run -d -p 8888:8888 -v vectorai-scans:/app/scans ghcr.io/zebbern/vectorai:latest
```

---

## 📖 Documentation & Usage

For a complete manual, see the **[User Guide](USERGUIDE.md)**. Below are the core ways to use the system.

### 1. The Full Workflow (Start to Finish)

**Step 1: Start a Scan**
Send a request to start a workflow. The server returns a `job_id`.

```bash
curl -X POST http://localhost:8888/api/workflow/bug-bounty-quick \
     -H "Content-Type: application/json" \
     -d '{"target": "scanme.nmap.org"}'

# Response Example:
# {
#   "status": "started", 
#   "job_id": "job_20240101_12345", 
#   "message": "Bug Bounty Quick Workflow initiated"
# }
```

**Step 2: Check Status**
Use the `job_id` from Step 1 to see provided progress.

```bash
curl http://localhost:8888/api/jobs/job_20240101_12345

# Response Example:
# { "status": "running", "progress": 45, "current_step": "Subdomain Enumeration" }
```

**Step 3: Get Results**
Once the status is `completed`, retrieve the full JSON report.

```bash
curl http://localhost:8888/api/report/job_20240101_12345
```

### 2. Available Workflows

Don't just guess! Here are the powerful built-in modes you can trigger via POST requests:

| Workflow | Endpoint | Description |
| :--- | :--- | :--- |
| **⚡ Quick Recon** | `/api/workflow/bug-bounty-quick` | Fast subdomain enumeration & basic port scan. |
| **🔍 Full Recon** | `/api/workflow/full-recon` | Deep dive: tech stack detection, DNS, subdomains, & crawling. |
| **🛡️ Vuln Scan** | `/api/workflow/vuln-assessment` | Active vulnerability scanning (Nuclei, Nikto, etc.). |
| **🚩 Red Team** | `/api/workflow/red-team-full` | Full kill-chain simulation (Recon -> Exploit attempts). |
| **☁️ API Scan** | `/api/workflow/api-pentest` | Specialized scanning for REST/GraphQL APIs. |

### 3. Running Specific Tools (Ad-Hoc)

You can also use VectorAI as a wrapper to run specific tools directly without running a full workflow. This allows you to leverage the server's environment.

```bash
curl -X POST http://localhost:8888/api/command/quick \
     -H "Content-Type: application/json" \
     -d '{"command": "nmap -sV -p80,443 scanme.nmap.org"}'
```

---

## ⚠️ Disclaimer

**VectorAI is for authorized security testing and educational purposes only.**
Using this tool against target systems without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

*Developed by @zebbern for the Security Community.*

