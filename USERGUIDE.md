# VectorAI User Guide

## Overview
VectorAI is an advanced, AI-powered penetration testing framework designed for Bug Bounties, CTFs, and Red Teaming. It leverages a modular architecture to separate the API interface from the core hacking logic, ensuring stability and extensibility.

## Architecture
The system is divided into two main components:

1.  **`vectorai_server.py` (The Interface)**
    *   Acts as the API Gateway and Web Server (Flask).
    *   Handles incoming requests, job management, and user interaction.
    *   Delegates actual tasks to the `vectorai_app` package.

2.  **`vectorai_app/` (The Core Logic)**
    *   **`core/`**: The "Brain." Contains the AI Decision Engine, Reconnaissance modules, and Intelligence systems.
    *   **`workflows/`**: The "Playbooks." Specialized logic for Bug Bounties, CTFs, and Network Pentesting.
    *   **`tools/`**: The "Toolbox." Wrappers and managers for external security tools (Nmap, Nuclei, etc.).
    *   **`tests/`**: Comprehensive unit tests to ensure system stability.

## Installation

1.  **Prerequisites**
    *   Python 3.8+
    *   Docker (optional, for containerized deployment)

2.  **Setup**
    Navigate to the project directory:
    ```bash
    cd hexstrike-docker
    ```

    Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Running the Server

To start the VectorAI server:

```bash
python vectorai_server.py
```

*   **Port**: 8888 (Default)
*   **Host**: 0.0.0.0 (Accessible from network)

## Verification & Testing

### 1. Health Check
Verify the server is running and responsive:
```bash
curl http://localhost:8888/health
```
**Expected Output:** `{"status": "healthy", ...}`

### 2. Live Integration Test
You can test the command execution engine with a simple API call:

**Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8888/api/command/quick" -Method Post -ContentType "application/json" -Body '{"command": "echo VectorAI_Online"}'
```

**Request (cURL):**
```bash
curl -X POST http://localhost:8888/api/command/quick \
     -H "Content-Type: application/json" \
     -d '{"command": "echo VectorAI_Online"}'
```

### 3. Running Unit Tests
To verify the internal logic without running the server:
```bash
python -m pytest vectorai_app/tests/
```

## Key API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Server health status |
| `/api/command/quick` | POST | Execute a fast, single command |
| `/api/workflow/bug-bounty-quick` | POST | Start a quick bug bounty recon scan |
| `/api/workflow/full-recon` | POST | Start a deep reconnaissance workflow |
| `/api/jobs` | GET | List all active and past jobs |

## Troubleshooting

*   **ImportError: No module named 'vectorai_app'**
    *   Ensure you are running the script from the `hexstrike-docker` directory.
    *   If running from outside, set PYTHONPATH: `$env:PYTHONPATH = "$PWD/hexstrike-docker"`

*   **Port 8888 in use**
    *   Edit `vectorai_app/config/settings.py` to change the `API_PORT`.
