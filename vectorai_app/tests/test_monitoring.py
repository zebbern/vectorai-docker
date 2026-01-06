import unittest
import time
import threading
from vectorai_app.core.monitoring import ResourceMonitor, PerformanceDashboard

class TestResourceMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ResourceMonitor(history_size=10)

    def test_get_current_usage(self):
        usage = self.monitor.get_current_usage()
        self.assertIn("cpu_percent", usage)
        self.assertIn("memory_percent", usage)
        self.assertIn("disk_percent", usage)
        self.assertIn("timestamp", usage)
        
        # Check history
        self.assertEqual(len(self.monitor.usage_history), 1)

    def test_history_limit(self):
        for _ in range(15):
            self.monitor.get_current_usage()
        
        self.assertEqual(len(self.monitor.usage_history), 10)

    def test_get_usage_trends(self):
        # Add some dummy data
        with self.monitor.history_lock:
            self.monitor.usage_history = [
                {"cpu_percent": 10.0, "memory_percent": 20.0},
                {"cpu_percent": 20.0, "memory_percent": 30.0}
            ]
        
        trends = self.monitor.get_usage_trends()
        self.assertEqual(trends["cpu_avg_10"], 15.0)
        self.assertEqual(trends["memory_avg_10"], 25.0)

class TestPerformanceDashboard(unittest.TestCase):
    def setUp(self):
        self.dashboard = PerformanceDashboard()

    def test_record_execution(self):
        result = {
            "success": True,
            "execution_time": 1.5,
            "return_code": 0
        }
        self.dashboard.record_execution("test_command", result)
        
        self.assertEqual(len(self.dashboard.execution_history), 1)
        self.assertEqual(self.dashboard.execution_history[0]["command"], "test_command")
        self.assertTrue(self.dashboard.execution_history[0]["success"])

    def test_get_summary(self):
        self.dashboard.record_execution("cmd1", {"success": True, "execution_time": 1.0})
        self.dashboard.record_execution("cmd2", {"success": False, "execution_time": 2.0})
        
        summary = self.dashboard.get_summary()
        self.assertEqual(summary["total_executions"], 2)
        self.assertEqual(summary["success_rate"], 50.0)
        self.assertEqual(summary["avg_execution_time"], 1.5)

if __name__ == '__main__':
    unittest.main()
