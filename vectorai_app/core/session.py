import sqlite3
import hashlib
import time
import os
import json
import logging
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Session storage paths
# These should ideally come from settings, but for now we use defaults or what was in the file
SCANS_DIR = Path("/app/scans")
DB_PATH = SCANS_DIR / "vectorai_sessions.db"

class SessionManager:
    """Manages scan sessions with SQLite database and file storage"""
    
    def __init__(self):
        self.scans_dir = SCANS_DIR
        self.db_path = DB_PATH
        self._init_storage()
        self._init_database()
    
    def _init_storage(self):
        """Initialize storage directories"""
        self.scans_dir.mkdir(parents=True, exist_ok=True)
    
    def _init_database(self):
        """Initialize SQLite database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Sessions table
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    session_type TEXT DEFAULT 'manual',
                    status TEXT DEFAULT 'running',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    total_jobs INTEGER DEFAULT 0,
                    completed_jobs INTEGER DEFAULT 0,
                    failed_jobs INTEGER DEFAULT 0,
                    notes TEXT
                );
                
                -- Jobs table (linked to sessions)
                CREATE TABLE IF NOT EXISTS session_jobs (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    exit_code INTEGER,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    execution_time REAL,
                    output_file TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );
                
                -- Findings table (parsed results)
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    job_id TEXT,
                    tool_name TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    title TEXT,
                    description TEXT,
                    target TEXT,
                    evidence TEXT,
                    raw_output TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id),
                    FOREIGN KEY (job_id) REFERENCES session_jobs(id)
                );
                
                -- Discovered assets table
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source_tool TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id),
                    UNIQUE(session_id, asset_type, value)
                );
                
                -- Create indexes for performance
                CREATE INDEX IF NOT EXISTS idx_session_jobs_session ON session_jobs(session_id);
                CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_assets_session ON assets(session_id);
                CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
            """)
            conn.commit()
    
    def create_session(self, target: str, session_type: str = "manual", notes: str = "") -> str:
        """Create a new scan session"""
        session_id = hashlib.md5(f"{target}_{time.time()}_{os.urandom(4).hex()}".encode()).hexdigest()[:16]
        
        # Create session directory
        session_dir = self.scans_dir / f"{datetime.now().strftime('%Y-%m-%d')}_{target.replace('.', '_').replace('/', '_')}_{session_id[:8]}"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "raw").mkdir(exist_ok=True)
        (session_dir / "parsed").mkdir(exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO sessions (id, target, session_type, notes)
                VALUES (?, ?, ?, ?)
            """, (session_id, target, session_type, notes))
            conn.commit()
        
        # Store session dir path in metadata
        self._update_session_metadata(session_id, {"dir": str(session_dir)})
        
        return session_id
    
    def _update_session_metadata(self, session_id: str, metadata: dict):
        """Store session metadata as JSON in notes field"""
        with sqlite3.connect(self.db_path) as conn:
            current = conn.execute("SELECT notes FROM sessions WHERE id = ?", (session_id,)).fetchone()
            try:
                existing = json.loads(current[0]) if current and current[0] else {}
            except:
                existing = {}
            existing.update(metadata)
            conn.execute("UPDATE sessions SET notes = ? WHERE id = ?", (json.dumps(existing), session_id))
            conn.commit()
    
    def get_session_dir(self, session_id: str) -> Optional[Path]:
        """Get session directory path"""
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute("SELECT notes FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if result and result[0]:
                try:
                    metadata = json.loads(result[0])
                    return Path(metadata.get("dir", ""))
                except:
                    pass
        return None
    
    def add_job(self, session_id: str, job_id: str, tool_name: str, command: str) -> bool:
        """Add a job to a session"""
        try:
            session_dir = self.get_session_dir(session_id)
            output_file = str(session_dir / "raw" / f"{tool_name}_{job_id[:8]}.txt") if session_dir else None
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO session_jobs (id, session_id, tool_name, command, output_file)
                    VALUES (?, ?, ?, ?, ?)
                """, (job_id, session_id, tool_name, command, output_file))
                conn.execute("UPDATE sessions SET total_jobs = total_jobs + 1 WHERE id = ?", (session_id,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"[!!] Error adding job to session: {e}")
            return False
    
    def update_job_result(self, job_id: str, status: str, exit_code: int, 
                          execution_time: float, output: str) -> bool:
        """Update job result and save output to file"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get job info
                job = conn.execute("""
                    SELECT session_id, output_file, tool_name FROM session_jobs WHERE id = ?
                """, (job_id,)).fetchone()
                
                if not job:
                    return False
                
                session_id, output_file, tool_name = job
                
                # Save raw output to file
                if output_file and output:
                    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                    with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                        f.write(f"# Tool: {tool_name}\n")
                        f.write(f"# Job ID: {job_id}\n")
                        f.write(f"# Timestamp: {datetime.now().isoformat()}\n")
                        f.write(f"# Exit Code: {exit_code}\n")
                        f.write(f"# Execution Time: {execution_time:.2f}s\n")
                        f.write("=" * 80 + "\n\n")
                        f.write(output)
                
                # Update job in database
                conn.execute("""
                    UPDATE session_jobs 
                    SET status = ?, exit_code = ?, execution_time = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (status, exit_code, execution_time, job_id))
                
                # Update session counters
                if status == "completed":
                    conn.execute("UPDATE sessions SET completed_jobs = completed_jobs + 1 WHERE id = ?", (session_id,))
                elif status == "failed":
                    conn.execute("UPDATE sessions SET failed_jobs = failed_jobs + 1 WHERE id = ?", (session_id,))
                
                conn.commit()
                
                # Parse and store findings
                self._parse_and_store_findings(session_id, job_id, tool_name, output)
                
                return True
        except Exception as e:
            logger.error(f"[!!] Error updating job result: {e}")
            return False
    
    def _parse_and_store_findings(self, session_id: str, job_id: str, tool_name: str, output: str):
        """Parse tool output and store findings/assets"""
        if not output:
            return
        
        findings = []
        assets = []
        
        # Tool-specific parsing
        if "nuclei" in tool_name.lower():
            findings.extend(self._parse_nuclei_output(output))
        elif "nmap" in tool_name.lower():
            findings.extend(self._parse_nmap_output(output))
            assets.extend(self._parse_nmap_ports(output))
        elif "subfinder" in tool_name.lower() or "amass" in tool_name.lower():
            assets.extend(self._parse_subdomain_output(output))
        elif "ffuf" in tool_name.lower() or "gobuster" in tool_name.lower() or "feroxbuster" in tool_name.lower():
            assets.extend(self._parse_directory_output(output))
        elif "httpx" in tool_name.lower():
            assets.extend(self._parse_httpx_output(output))
        elif "gau" in tool_name.lower() or "waybackurls" in tool_name.lower():
            assets.extend(self._parse_url_output(output))
        
        # Store findings
        with sqlite3.connect(self.db_path) as conn:
            for finding in findings:
                conn.execute("""
                    INSERT INTO findings (session_id, job_id, tool_name, finding_type, severity, title, description, target, evidence, raw_output)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (session_id, job_id, tool_name, finding.get("type", "unknown"), 
                      finding.get("severity", "info"), finding.get("title", ""),
                      finding.get("description", ""), finding.get("target", ""),
                      finding.get("evidence", ""), finding.get("raw", "")[:2000]))
            
            # Store assets (ignore duplicates)
            for asset in assets:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO assets (session_id, asset_type, value, source_tool, metadata)
                        VALUES (?, ?, ?, ?, ?)
                    """, (session_id, asset.get("type", "unknown"), asset.get("value", ""),
                          tool_name, json.dumps(asset.get("metadata", {}))))
                except:
                    pass
            
            conn.commit()
    
    def _parse_nuclei_output(self, output: str) -> List[Dict]:
        """Parse Nuclei output for findings"""
        findings = []
        # Nuclei format: [template-id] [protocol] [severity] target [extra-info]
        # Example: [cve-2021-44228] [http] [critical] https://target.com
        pattern = r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)(?:\s*\[([^\]]+)\])?'
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('[INF]') or line.startswith('[WRN]'):
                continue
            
            match = re.search(pattern, line)
            if match:
                template_id, protocol, severity, target = match.groups()[:4]
                extra = match.group(5) if match.lastindex >= 5 else ""
                
                findings.append({
                    "type": "vulnerability",
                    "severity": severity.lower(),
                    "title": template_id,
                    "description": f"Nuclei detected {template_id} via {protocol}",
                    "target": target,
                    "evidence": extra or line,
                    "raw": line
                })
        
        return findings
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse Nmap output for vulnerability findings"""
        findings = []
        
        # Look for vulnerability script outputs
        vuln_patterns = [
            r'(CVE-\d{4}-\d+)',
            r'VULNERABLE',
            r'State:\s*VULNERABLE',
        ]
        
        for line in output.split('\n'):
            for pattern in vuln_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract CVE if present
                    cve_match = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
                    findings.append({
                        "type": "vulnerability",
                        "severity": "high" if cve_match else "medium",
                        "title": cve_match.group(1) if cve_match else "Nmap Vulnerability",
                        "description": line.strip(),
                        "target": "",
                        "evidence": line,
                        "raw": line
                    })
                    break
        
        return findings
    
    def _parse_nmap_ports(self, output: str) -> List[Dict]:
        """Parse Nmap output for open ports"""
        assets = []
        # Pattern: 22/tcp open ssh OpenSSH 7.4
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?'
        
        for line in output.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                port, protocol, service, version = match.groups()
                assets.append({
                    "type": "open_port",
                    "value": f"{port}/{protocol}",
                    "metadata": {
                        "service": service,
                        "version": version.strip() if version else "",
                        "raw": line.strip()
                    }
                })
        
        return assets
    
    def _parse_subdomain_output(self, output: str) -> List[Dict]:
        """Parse subdomain enumeration output"""
        assets = []
        seen = set()
        
        for line in output.split('\n'):
            line = line.strip()
            # Match domain patterns
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$', line):
                if line not in seen:
                    seen.add(line)
                    assets.append({
                        "type": "subdomain",
                        "value": line,
                        "metadata": {}
                    })
        
        return assets
    
    def _parse_directory_output(self, output: str) -> List[Dict]:
        """Parse directory brute-force output"""
        assets = []
        seen = set()
        
        # Match URLs or paths with status codes
        url_pattern = r'(https?://[^\s]+|/[^\s]*)\s*(?:\[(\d{3})\]|\(Status:\s*(\d{3})\)|(\d{3}))'
        
        for line in output.split('\n'):
            match = re.search(url_pattern, line)
            if match:
                path = match.group(1)
                status = match.group(2) or match.group(3) or match.group(4)
                if path not in seen:
                    seen.add(path)
                    assets.append({
                        "type": "endpoint",
                        "value": path,
                        "metadata": {"status_code": status}
                    })
        
        return assets
    
    def _parse_httpx_output(self, output: str) -> List[Dict]:
        """Parse httpx output for live hosts"""
        assets = []
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('http'):
                # Extract URL and any metadata
                parts = line.split()
                url = parts[0] if parts else line
                assets.append({
                    "type": "live_host",
                    "value": url,
                    "metadata": {"raw": line}
                })
        
        return assets
    
    def _parse_url_output(self, output: str) -> List[Dict]:
        """Parse URL discovery output (gau, waybackurls)"""
        assets = []
        seen = set()
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('http') and line not in seen:
                seen.add(line)
                # Check for interesting patterns
                interesting = any(p in line.lower() for p in ['api', 'admin', 'login', 'config', '.json', '.xml', 'graphql', 'swagger'])
                assets.append({
                    "type": "url",
                    "value": line,
                    "metadata": {"interesting": interesting}
                })
        
        return assets
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            session = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if session:
                return dict(session)
        return None
    
    def get_session_jobs(self, session_id: str) -> List[Dict]:
        """Get all jobs for a session"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            jobs = conn.execute("SELECT * FROM session_jobs WHERE session_id = ? ORDER BY started_at", (session_id,)).fetchall()
            return [dict(job) for job in jobs]
    
    def get_session_findings(self, session_id: str, severity: str = None) -> List[Dict]:
        """Get findings for a session, optionally filtered by severity"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if severity:
                findings = conn.execute("""
                    SELECT * FROM findings WHERE session_id = ? AND severity = ? ORDER BY created_at
                """, (session_id, severity)).fetchall()
            else:
                findings = conn.execute("""
                    SELECT * FROM findings WHERE session_id = ? ORDER BY 
                    CASE severity 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                        ELSE 5 
                    END, created_at
                """, (session_id,)).fetchall()
            return [dict(f) for f in findings]
    
    def get_session_assets(self, session_id: str, asset_type: str = None) -> List[Dict]:
        """Get discovered assets for a session"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if asset_type:
                assets = conn.execute("""
                    SELECT * FROM assets WHERE session_id = ? AND asset_type = ?
                """, (session_id, asset_type)).fetchall()
            else:
                assets = conn.execute("""
                    SELECT * FROM assets WHERE session_id = ? ORDER BY asset_type, value
                """, (session_id,)).fetchall()
            return [dict(a) for a in assets]
    
    def get_session_summary(self, session_id: str) -> Dict:
        """Get session summary with counts"""
        with sqlite3.connect(self.db_path) as conn:
            session = self.get_session(session_id)
            if not session:
                return {"error": "Session not found"}
            
            # Count findings by severity
            findings_counts = {}
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = conn.execute("""
                    SELECT COUNT(*) FROM findings WHERE session_id = ? AND severity = ?
                """, (session_id, severity)).fetchone()[0]
                findings_counts[severity] = count
            
            # Count assets by type
            asset_counts = {}
            for row in conn.execute("""
                SELECT asset_type, COUNT(*) FROM assets WHERE session_id = ? GROUP BY asset_type
            """, (session_id,)):
                asset_counts[row[0]] = row[1]
            
            return {
                "session_id": session_id,
                "target": session.get("target"),
                "status": session.get("status"),
                "created_at": session.get("created_at"),
                "jobs": {
                    "total": session.get("total_jobs", 0),
                    "completed": session.get("completed_jobs", 0),
                    "failed": session.get("failed_jobs", 0)
                },
                "findings": findings_counts,
                "assets": asset_counts
            }
    
    def complete_session(self, session_id: str):
        """Mark session as completed"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE sessions SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?
            """, (session_id,))
            conn.commit()
    
    def list_sessions(self, limit: int = 20) -> List[Dict]:
        """List recent sessions"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            sessions = conn.execute("""
                SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(s) for s in sessions]
    
    def generate_session_report(self, session_id: str, format: str = "json") -> Dict:
        """Generate comprehensive session report"""
        session = self.get_session(session_id)
        if not session:
            return {"error": "Session not found"}
        
        summary = self.get_session_summary(session_id)
        findings = self.get_session_findings(session_id)
        assets = self.get_session_assets(session_id)
        
        report = {
            "report_generated": datetime.now().isoformat(),
            "session": session,
            "summary": summary,
            "findings": {
                "critical": [f for f in findings if f.get("severity") == "critical"],
                "high": [f for f in findings if f.get("severity") == "high"],
                "medium": [f for f in findings if f.get("severity") == "medium"],
                "low": [f for f in findings if f.get("severity") == "low"],
                "info": [f for f in findings if f.get("severity") == "info"]
            },
            "assets": {}
        }
        
        # Group assets by type
        for asset in assets:
            asset_type = asset.get("asset_type", "unknown")
            if asset_type not in report["assets"]:
                report["assets"][asset_type] = []
            report["assets"][asset_type].append(asset.get("value"))
        
        if format == "markdown":
            return self._generate_markdown_report(report)
        
        return report
    
    def _generate_markdown_report(self, report: Dict) -> Dict:
        """Generate markdown format report"""
        session = report.get("session", {})
        summary = report.get("summary", {})
        findings = report.get("findings", {})
        assets = report.get("assets", {})
        
        md = f"# Security Assessment Report\n"
        md += f"**Target:** {session.get('target', 'N/A')}  \n"
        md += f"**Session ID:** {session.get('id', 'N/A')}  \n"
        md += f"**Generated:** {report.get('report_generated', 'N/A')}  \n"
        md += f"**Status:** {session.get('status', 'N/A')}\n\n"
        
        return {"content": md}

# Global session manager
session_manager = SessionManager()
