import unittest
import os
import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from vectorai_app.core.session import SessionManager

class TestSessionManager(unittest.TestCase):
    def setUp(self):
        # Create a mock for the Path class
        self.path_patcher = patch('vectorai_app.core.session.Path')
        self.mock_path_cls = self.path_patcher.start()
        
        # Create a mock for the Path instance
        self.mock_scans_dir = MagicMock()
        self.mock_path_cls.return_value = self.mock_scans_dir
        
        # Configure __truediv__ (the / operator) to return another mock
        self.mock_session_dir = MagicMock()
        self.mock_scans_dir.__truediv__.return_value = self.mock_session_dir
        self.mock_session_dir.__truediv__.return_value = self.mock_session_dir # Allow chaining
        
        self.mock_db_path = self.mock_scans_dir / "vectorai_sessions.db"
        
        self.sqlite_patcher = patch('vectorai_app.core.session.sqlite3')
        self.mock_sqlite = self.sqlite_patcher.start()
        
        # Setup mock connection and cursor
        self.mock_conn = MagicMock()
        self.mock_cursor = MagicMock()
        self.mock_sqlite.connect.return_value.__enter__.return_value = self.mock_conn
        self.mock_conn.execute.return_value = self.mock_cursor
        self.mock_conn.executescript.return_value = None
        
        # Initialize SessionManager
        with patch('vectorai_app.core.session.SCANS_DIR', self.mock_scans_dir), \
             patch('vectorai_app.core.session.DB_PATH', self.mock_db_path):
            self.session_manager = SessionManager()

    def tearDown(self):
        self.path_patcher.stop()
        self.sqlite_patcher.stop()

    def test_init(self):
        """Test initialization of SessionManager"""
        # Verify storage init
        self.mock_scans_dir.mkdir.assert_called_with(parents=True, exist_ok=True)
        
        # Verify database init
        self.mock_sqlite.connect.assert_called()
        self.mock_conn.executescript.assert_called()

    def test_create_session(self):
        """Test creating a new session"""
        target = "example.com"
        session_type = "manual"
        notes = "test session"
        
        session_id = self.session_manager.create_session(target, session_type, notes)
        
        self.assertTrue(len(session_id) > 0)
        
        # Verify DB insert
        self.mock_conn.execute.assert_called()
        # Check if INSERT INTO sessions was called
        calls = [c for c in self.mock_conn.execute.call_args_list if "INSERT INTO sessions" in c[0][0]]
        self.assertTrue(len(calls) > 0)
        
        # Verify commit
        self.mock_conn.commit.assert_called()

    def test_add_job(self):
        """Test adding a job to a session"""
        session_id = "test_session_id"
        job_id = "test_job_id"
        tool_name = "nmap"
        command = "nmap -sV example.com"
        
        # Mock get_session_dir
        with patch.object(self.session_manager, 'get_session_dir', return_value=Path("/tmp/scans/session_1")):
            result = self.session_manager.add_job(session_id, job_id, tool_name, command)
            
            self.assertTrue(result)
            
            # Verify DB insert
            calls = [c for c in self.mock_conn.execute.call_args_list if "INSERT INTO session_jobs" in c[0][0]]
            self.assertTrue(len(calls) > 0)
            
            # Verify update total_jobs
            calls = [c for c in self.mock_conn.execute.call_args_list if "UPDATE sessions SET total_jobs" in c[0][0]]
            self.assertTrue(len(calls) > 0)

    def test_update_job_result_success(self):
        """Test updating a job result successfully"""
        job_id = "test_job_id"
        status = "completed"
        exit_code = 0
        execution_time = 1.5
        output = "Scan results..."
        
        # Mock DB return for job info
        self.mock_cursor.fetchone.return_value = ("session_id", "/tmp/output.txt", "nmap")
        
        with patch('builtins.open', mock_open()) as mock_file:
            result = self.session_manager.update_job_result(job_id, status, exit_code, execution_time, output)
            
            self.assertTrue(result)
            
            # Verify file write
            mock_file.assert_called_with("/tmp/output.txt", 'w', encoding='utf-8', errors='replace')
            
            # Verify DB update
            calls = [c for c in self.mock_conn.execute.call_args_list if "UPDATE session_jobs" in c[0][0]]
            self.assertTrue(len(calls) > 0)
            
            # Verify session counters update
            calls = [c for c in self.mock_conn.execute.call_args_list if "UPDATE sessions SET completed_jobs" in c[0][0]]
            self.assertTrue(len(calls) > 0)

    def test_parse_nuclei_output(self):
        """Test parsing Nuclei output"""
        output = """[cve-2021-44228] [http] [critical] https://target.com
[info-disclosure] [http] [low] https://target.com/config"""
        
        findings = self.session_manager._parse_nuclei_output(output)
        
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]['title'], 'cve-2021-44228')
        self.assertEqual(findings[0]['severity'], 'critical')
        self.assertEqual(findings[1]['title'], 'info-disclosure')
        self.assertEqual(findings[1]['severity'], 'low')

    def test_parse_nmap_output(self):
        """Test parsing Nmap output"""
        output = """
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4
80/tcp open  http    Apache httpd 2.4.6
| http-vuln-cve2017-5638: 
|   VULNERABLE:
|   Apache Struts 2 Remote Code Execution
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-5638
        """
        
        # Test port parsing
        assets = self.session_manager._parse_nmap_ports(output)
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0]['value'], '22/tcp')
        self.assertEqual(assets[1]['value'], '80/tcp')
        
        # Test vulnerability parsing
        findings = self.session_manager._parse_nmap_output(output)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]['type'], 'vulnerability')
        
        # Check if any finding contains the CVE
        cve_found = any('CVE-2017-5638' in f['title'] for f in findings)
        self.assertTrue(cve_found, "CVE-2017-5638 not found in findings titles")

if __name__ == '__main__':
    unittest.main()
