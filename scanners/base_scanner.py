import os
import json
import logging
from datetime import datetime
from abc import ABC, abstractmethod
from config import Config

logger = logging.getLogger(__name__)
config = Config()

class BaseScanner(ABC):
    def __init__(self, github_client, storage_client=None):
        self.github_client = github_client
        self.storage_client = storage_client
        self.org = github_client.org
        self.scan_type = self.__class__.__name__
        logger.info(f"Initialized {self.scan_type} for {self.org}")
        
    @abstractmethod
    def scan(self):
        """Implement this method in subclasses to perform the scan"""
        pass
        
    def save_report(self, data):
        """Save report locally and to cloud storage if configured"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.org}_{self.scan_type}_{timestamp}.json"
        local_path = os.path.join(config.REPORTS_DIR, filename)
        
        # Ensure report directory exists
        os.makedirs(config.REPORTS_DIR, exist_ok=True)
        
        # Add metadata to report
        data['generated_at'] = datetime.now().isoformat()
        data['organization'] = self.org
        data['scan_type'] = self.scan_type.lower().replace('analyzer', '')
        
        # Save report locally
        with open(local_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Report saved locally to {local_path}")
        
        # Upload to cloud storage if configured
        gcs_path = None
        if self.storage_client:
            try:
                destination_blob = f"github_scanner/{data['scan_type']}/{filename}"
                gcs_path = self.storage_client.upload_file(
                    source_file=local_path,
                    destination_blob=destination_blob
                )
            except Exception as e:
                logger.error(f"Error uploading report to cloud storage: {str(e)}")
        
        # Update data with file paths
        data['report_file'] = {
            'local_path': local_path,
            'gcs_path': gcs_path
        }
        
        return data