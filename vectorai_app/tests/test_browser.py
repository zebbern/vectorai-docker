import unittest
from unittest.mock import patch, MagicMock
from vectorai_app.workflows.browser import BrowserAgent

class TestBrowserAgent(unittest.TestCase):
    def setUp(self):
        self.agent = BrowserAgent()

    @patch('vectorai_app.workflows.browser.webdriver')
    def test_setup_browser_success(self, mock_webdriver):
        mock_webdriver.Chrome.return_value = MagicMock()
        result = self.agent.setup_browser(headless=True)
        self.assertTrue(result)
        self.assertIsNotNone(self.agent.driver)

    @patch('vectorai_app.workflows.browser.webdriver')
    def test_setup_browser_failure(self, mock_webdriver):
        mock_webdriver.Chrome.side_effect = Exception("Failed")
        result = self.agent.setup_browser(headless=True)
        self.assertFalse(result)
        self.assertIsNone(self.agent.driver)

    def test_analyze_page_security(self):
        page_info = {
            'local_storage': {'secret_key': '12345'},
            'session_storage': {},
            'forms': [{'action': '/login', 'method': 'POST', 'inputs': [{'name': 'username'}]}],
            'scripts': [{'type': 'inline'}]
        }
        
        result = self.agent._analyze_page_security("", page_info)
        
        self.assertEqual(result['total_issues'], 3)
        issue_types = [i['type'] for i in result['issues']]
        self.assertIn('sensitive_data_storage', issue_types)
        self.assertIn('missing_csrf_protection', issue_types)
        self.assertIn('inline_javascript', issue_types)

if __name__ == '__main__':
    unittest.main()
