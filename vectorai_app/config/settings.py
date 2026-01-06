import os

# API Configuration
API_PORT = int(os.environ.get('VECTORAI_PORT', 8888))
API_HOST = os.environ.get('VECTORAI_HOST', '127.0.0.1')

# Logging Configuration
LOG_DIR = '/app/logs'
LOG_FILE = 'VectorAI.log'

def get_log_config():
    """
    Determine the log directory and file path, handling permission issues.
    Returns a tuple (log_dir, log_file_path).
    """
    log_dir = LOG_DIR
    
    # Ensure log directory exists
    try:
        os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        # Fallback to local directory if /app/logs is not writable
        log_dir = '.'
    
    log_file_path = os.path.join(log_dir, LOG_FILE)
    return log_dir, log_file_path

# Command Execution Configuration
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
COMMAND_TIMEOUT_MAX = 1800  # 30 minutes max for long-running tools
