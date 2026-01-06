import unittest
from unittest.mock import patch, MagicMock
from vectorai_app.workflows.http_testing import HTTPTestingFramework

class TestHTTPTestingFramework(unittest.TestCase):
    def setUp(self):
        self.framework = HTTPTestingFramework()

    def test_intercept_request_get(self):
        self.framework.session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = "<html><body>Hello</body></html>"
        mock_response.content = b"<html><body>Hello</body></html>"
        mock_response.elapsed.total_seconds.return_value = 0.1
        mock_response.request.headers = {}
        
        self.framework.session.get.return_value = mock_response
        
        result = self.framework.intercept_request("http://example.com", method="GET")
        
        self.assertTrue(result['success'])
        self.assertEqual(result['response']['status_code'], 200)
        self.framework.session.get.assert_called_once()

    def test_match_replace(self):
        self.framework.set_match_replace_rules([
            {'where': 'url', 'pattern': 'foo', 'replacement': 'bar'}
        ])
        
        url, data, headers = self.framework._apply_match_replace("http://example.com/foo", None, {})
        self.assertEqual(url, "http://example.com/bar")

    def test_scope(self):
        self.framework.set_scope("example.com", include_subdomains=False)
        self.assertTrue(self.framework._in_scope("http://example.com/foo"))
        self.assertFalse(self.framework._in_scope("http://sub.example.com/foo"))

if __name__ == '__main__':
    unittest.main()
