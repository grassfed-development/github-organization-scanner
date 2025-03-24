import os
import logging
from datetime import datetime
from google.cloud import storage

logger = logging.getLogger(__name__)

class GCSClient:
    def __init__(self, bucket_name=None):
        self.bucket_name = bucket_name
        self.client = None
        self.bucket = None
        
        if bucket_name:
            try:
                self.client = storage.Client()
                self.bucket = self.client.bucket(bucket_name)
                logger.info(f"Initialized GCS client for bucket: {bucket_name}")
            except Exception as e:
                logger.error(f"Error initializing GCS client: {str(e)}")
                self.bucket = None
    
    def upload_file(self, source_file, destination_blob=None):
        """Upload a file to GCS bucket"""
        if not self.bucket:
            logger.warning("GCS bucket not configured, skipping upload")
            return None
            
        # If destination not specified, use source filename
        if not destination_blob:
            destination_blob = os.path.basename(source_file)
        
        try:
            blob = self.bucket.blob(destination_blob)
            blob.upload_from_filename(source_file)
            logger.info(f"Uploaded {source_file} to gs://{self.bucket_name}/{destination_blob}")
            return f"gs://{self.bucket_name}/{destination_blob}"
        except Exception as e:
            logger.error(f"Error uploading to GCS: {str(e)}")
            return None
    
    def upload_data(self, data, destination_blob):
        """Upload string or JSON data directly to GCS bucket"""
        if not self.bucket:
            logger.warning("GCS bucket not configured, skipping upload")
            return None
            
        try:
            blob = self.bucket.blob(destination_blob)
            
            if isinstance(data, (dict, list)):
                import json
                blob.upload_from_string(json.dumps(data, indent=2), content_type='application/json')
            else:
                blob.upload_from_string(str(data))
                
            logger.info(f"Uploaded data to gs://{self.bucket_name}/{destination_blob}")
            return f"gs://{self.bucket_name}/{destination_blob}"
        except Exception as e:
            logger.error(f"Error uploading data to GCS: {str(e)}")
            return None