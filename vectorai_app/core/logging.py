import logging
import sys
from vectorai_app.config.settings import get_log_config

def setup_logging():
    """
    Configure the logging system with file and console handlers.
    """
    log_dir, log_file = get_log_config()

    try:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_file)
            ]
        )
    except PermissionError:
        # Fallback to console-only logging if file creation fails
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )
