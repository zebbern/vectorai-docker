import unittest
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from vectorai_app.core.environment import PythonEnvironmentManager

class TestPythonEnvironmentManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.manager = PythonEnvironmentManager(base_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @patch('vectorai_app.core.environment.venv.create')
    def test_create_venv(self, mock_venv_create):
        env_name = "test_env"
        env_path = self.manager.create_venv(env_name)
        
        self.assertEqual(env_path, Path(self.test_dir) / env_name)
        mock_venv_create.assert_called_once()

    @patch('vectorai_app.core.environment.subprocess.run')
    @patch('vectorai_app.core.environment.venv.create')
    def test_install_package_success(self, mock_venv_create, mock_subprocess):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = self.manager.install_package("test_env", "requests")
        self.assertTrue(result)

    @patch('vectorai_app.core.environment.subprocess.run')
    @patch('vectorai_app.core.environment.venv.create')
    def test_install_package_failure(self, mock_venv_create, mock_subprocess):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Error"
        mock_subprocess.return_value = mock_result
        
        result = self.manager.install_package("test_env", "requests")
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
