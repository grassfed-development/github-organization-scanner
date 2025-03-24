import os
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

class Config:
    # GitHub settings
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
    GITHUB_ORG = os.getenv('GITHUB_ORG')
    
    # GCS settings
    GCS_BUCKET = os.getenv('GCS_BUCKET')
    
    # App settings
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Report settings
    REPORTS_DIR = os.getenv('REPORTS_DIR', 'reports')
    
    def __init__(self):
        # Create reports directory if it doesn't exist
        os.makedirs(self.REPORTS_DIR, exist_ok=True)