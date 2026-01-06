import unittest
import time
import threading
from unittest.mock import MagicMock, patch
from vectorai_app.core.execution import EnhancedProcessManager

class TestEnhancedProcessManager(unittest.TestCase):
    def setUp(self):
        self.manager = EnhancedProcessManager()
        # Mock process pool to avoid actual execution
        self.manager.process_pool = MagicMock()
        self.manager.process_pool.min_workers = 4
        self.manager.process_pool.max_workers = 32
        self.manager.process_pool.get_pool_stats.return_value = {"active_workers": 4, "queue_size": 0}

    def test_execute_command_async(self):
        task_id = self.manager.execute_command_async("echo test")
        self.assertTrue(task_id.startswith("cmd_"))
        self.manager.process_pool.submit_task.assert_called_once()

    def test_auto_scale_scale_up(self):
        # Mock resource usage low, demand high
        resource_usage = {"cpu_percent": 10.0, "memory_percent": 20.0}
        self.manager.process_pool.get_pool_stats.return_value = {"active_workers": 4, "queue_size": 10}
        
        self.manager._auto_scale_based_on_resources(resource_usage)
        self.manager.process_pool._scale_up.assert_called_once()

    def test_auto_scale_scale_down(self):
        # Mock resource usage high
        resource_usage = {"cpu_percent": 90.0, "memory_percent": 20.0}
        self.manager.process_pool.get_pool_stats.return_value = {"active_workers": 10, "queue_size": 0}
        
        self.manager._auto_scale_based_on_resources(resource_usage)
        self.manager.process_pool._scale_down.assert_called_once()

if __name__ == '__main__':
    unittest.main()
