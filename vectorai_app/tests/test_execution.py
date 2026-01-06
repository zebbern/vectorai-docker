
import unittest
from unittest.mock import MagicMock, patch
import time
from vectorai_app.core.execution import (
    execute_command, 
    execute_command_with_recovery, 
    ProcessManager, 
    VectorAICache,
    EnhancedCommandExecutor
)
from vectorai_app.core.models import RecoveryAction, ErrorType

class TestExecution(unittest.TestCase):

    def setUp(self):
        # Reset cache and process manager for each test
        self.cache = VectorAICache()
        ProcessManager.active_processes = {}

    @patch('vectorai_app.core.execution.EnhancedCommandExecutor')
    def test_execute_command_success(self, mock_executor_cls):
        # Setup mock
        mock_executor = mock_executor_cls.return_value
        mock_executor.execute.return_value = {
            "success": True,
            "stdout": "success output",
            "stderr": "",
            "return_code": 0
        }

        # Execute
        result = execute_command("echo test", use_cache=False)

        # Verify
        self.assertTrue(result["success"])
        self.assertEqual(result["stdout"], "success output")
        mock_executor.execute.assert_called_once()

    @patch('vectorai_app.core.execution.EnhancedCommandExecutor')
    def test_execute_command_cache(self, mock_executor_cls):
        # Setup mock
        mock_executor = mock_executor_cls.return_value
        mock_executor.execute.return_value = {
            "success": True,
            "stdout": "cached output",
            "stderr": "",
            "return_code": 0
        }

        # Execute first time (should cache)
        execute_command("echo cache", use_cache=True)
        
        # Execute second time (should use cache)
        # We need to patch the global cache in the module, or just rely on the fact that 
        # execute_command uses the global cache instance.
        # Since we can't easily reset the global cache instance in the module without reloading,
        # we'll just verify that the executor is called only once if we mock the cache behavior 
        # or if we trust the global cache.
        
        # Actually, let's just test that the executor is NOT called the second time
        mock_executor.reset_mock()
        
        # We need to ensure the first call actually populated the cache.
        # The execute_command function uses the global 'cache' variable.
        # We can patch 'vectorai_app.core.execution.cache'
        
        with patch('vectorai_app.core.execution.cache') as mock_cache:
            mock_cache.get.return_value = {"success": True, "cached": True}
            
            result = execute_command("echo cache", use_cache=True)
            
            self.assertTrue(result.get("cached"))
            mock_executor.execute.assert_not_called()

    @patch('vectorai_app.core.execution.execute_command')
    @patch('vectorai_app.core.execution.error_handler')
    def test_execute_command_with_recovery_retry(self, mock_error_handler, mock_execute):
        # Setup mocks
        # First attempt fails, second succeeds
        mock_execute.side_effect = [
            {"success": False, "stderr": "timeout error"},
            {"success": True, "stdout": "recovered"}
        ]

        # Setup recovery strategy
        mock_strategy = MagicMock()
        mock_strategy.action = RecoveryAction.RETRY_WITH_BACKOFF
        mock_strategy.parameters = {"initial_delay": 0.1, "max_delay": 1}
        mock_strategy.backoff_multiplier = 1
        
        mock_error_handler.handle_tool_failure.return_value = mock_strategy

        # Execute
        result = execute_command_with_recovery("nmap", "nmap -T4 target")

        # Verify
        self.assertTrue(result["success"])
        self.assertEqual(result["recovery_info"]["attempts_made"], 2)
        self.assertTrue(result["recovery_info"]["recovery_applied"])

    @patch('vectorai_app.core.execution.execute_command')
    @patch('vectorai_app.core.execution.error_handler')
    def test_execute_command_with_recovery_exhausted(self, mock_error_handler, mock_execute):
        # Setup mocks - always fails
        mock_execute.return_value = {"success": False, "stderr": "persistent error"}

        # Setup recovery strategy
        mock_strategy = MagicMock()
        mock_strategy.action = RecoveryAction.RETRY_WITH_BACKOFF
        mock_strategy.parameters = {"initial_delay": 0.01, "max_delay": 0.1}
        mock_strategy.backoff_multiplier = 1
        
        mock_error_handler.handle_tool_failure.return_value = mock_strategy

        # Execute
        result = execute_command_with_recovery("nmap", "nmap -T4 target", max_attempts=2)

        # Verify
        self.assertFalse(result["success"])
        self.assertEqual(result["recovery_info"]["attempts_made"], 2)
        self.assertEqual(result["recovery_info"]["final_action"], "all_attempts_exhausted")

if __name__ == '__main__':
    unittest.main()
