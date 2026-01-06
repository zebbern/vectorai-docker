import unittest
from vectorai_app.core.payloads import AIPayloadGenerator

class TestAIPayloadGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = AIPayloadGenerator()

    def test_generate_contextual_payload_xss(self):
        target_info = {
            "attack_type": "xss",
            "complexity": "basic",
            "technology": "php"
        }
        result = self.generator.generate_contextual_payload(target_info)
        
        self.assertEqual(result["attack_type"], "xss")
        self.assertGreater(len(result["payloads"]), 0)
        self.assertGreater(len(result["test_cases"]), 0)

    def test_generate_contextual_payload_sqli(self):
        target_info = {
            "attack_type": "sqli",
            "complexity": "advanced",
            "technology": "mysql"
        }
        result = self.generator.generate_contextual_payload(target_info)
        
        self.assertEqual(result["attack_type"], "sqli")
        self.assertGreater(len(result["payloads"]), 0)

    def test_assess_risk_level(self):
        self.assertEqual(self.generator._assess_risk_level("cat /etc/passwd"), "HIGH")
        self.assertEqual(self.generator._assess_risk_level("<script>alert(1)</script>"), "MEDIUM")
        self.assertEqual(self.generator._assess_risk_level("hello world"), "LOW")

if __name__ == '__main__':
    unittest.main()
