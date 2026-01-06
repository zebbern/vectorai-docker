import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add the project root to the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from vectorai_app.core.correlation import VulnerabilityCorrelator

class TestVulnerabilityCorrelator(unittest.TestCase):
    def setUp(self):
        self.correlator = VulnerabilityCorrelator()

    def test_find_attack_chains_success(self):
        """Test finding attack chains successfully"""
        # Mock _find_vulnerabilities_by_pattern to return predictable data
        with patch.object(self.correlator, '_find_vulnerabilities_by_pattern') as mock_find:
            mock_find.side_effect = [
                # Initial access (remote_execution)
                [{
                    "cve_id": "CVE-2024-1111",
                    "description": "RCE in Apache",
                    "cvss_score": 9.8,
                    "exploitability": "HIGH"
                }],
                # Privilege escalation
                [{
                    "cve_id": "CVE-2024-2222",
                    "description": "PrivEsc in Linux",
                    "cvss_score": 7.8,
                    "exploitability": "MEDIUM"
                }],
                # Persistence
                [{
                    "cve_id": "CVE-2024-3333",
                    "description": "Persistence via cron",
                    "cvss_score": 6.5,
                    "exploitability": "LOW"
                }]
            ]

            result = self.correlator.find_attack_chains("Apache", max_depth=3)

            self.assertTrue(result["success"])
            self.assertEqual(result["total_chains"], 1)
            self.assertEqual(len(result["attack_chains"]), 1)
            
            chain = result["attack_chains"][0]
            self.assertEqual(len(chain["stages"]), 3)
            self.assertEqual(chain["stages"][0]["objective"], "Initial Access")
            self.assertEqual(chain["stages"][1]["objective"], "Privilege Escalation")
            self.assertEqual(chain["stages"][2]["objective"], "Persistence")

    def test_find_attack_chains_no_vulns(self):
        """Test finding attack chains when no vulnerabilities are found"""
        with patch.object(self.correlator, '_find_vulnerabilities_by_pattern') as mock_find:
            mock_find.return_value = []

            result = self.correlator.find_attack_chains("Nginx")

            self.assertTrue(result["success"])
            self.assertEqual(result["total_chains"], 0)
            self.assertEqual(len(result["attack_chains"]), 0)

    def test_find_attack_chains_error(self):
        """Test error handling in find_attack_chains"""
        with patch.object(self.correlator, '_find_vulnerabilities_by_pattern') as mock_find:
            mock_find.side_effect = Exception("Database error")

            result = self.correlator.find_attack_chains("IIS")

            self.assertFalse(result["success"])
            self.assertIn("Database error", result["error"])

    def test_generate_chain_recommendations(self):
        """Test recommendation generation"""
        chains = [
            {
                "overall_probability": 0.8,
                "stages": []
            },
            {
                "overall_probability": 0.5,
                "stages": []
            }
        ]
        
        recommendations = self.correlator._generate_chain_recommendations(chains)
        
        self.assertIn("Found 2 potential attack chains", recommendations)
        self.assertIn("Highest probability chain: 80.00%", recommendations)

if __name__ == '__main__':
    unittest.main()
