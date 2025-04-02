import os
import logging
import json
from typing import Dict, List, Any, Optional

# Import Google Cloud Secret Manager client
try:
    from google.cloud import secretmanager
    SECRET_MANAGER_AVAILABLE = True
except ImportError:
    SECRET_MANAGER_AVAILABLE = False

logger = logging.getLogger(__name__)

class GCPSecretClient:
    """Client for retrieving secrets from Google Cloud Secret Manager"""
    
    def __init__(self, project_id=None):
        """
        Initialize Secret Manager client with GCP project ID.
        
        Args:
            project_id: GCP project ID (default: environment variable GCP_PROJECT_ID)
        """
        self.project_id = project_id or os.environ.get('GCP_PROJECT_ID')
        self.client = None
        
        if not SECRET_MANAGER_AVAILABLE:
            logger.warning("Google Cloud Secret Manager client not available. "
                          "Install it using 'pip install google-cloud-secret-manager'")
            return
            
        if not self.project_id:
            logger.warning("No GCP project ID provided. Secret Manager integration disabled.")
            return
            
        try:
            self.client = secretmanager.SecretManagerServiceClient()
            logger.info(f"GCP Secret Manager client initialized for project {self.project_id}")
        except Exception as e:
            logger.error(f"Failed to initialize Secret Manager client: {str(e)}")
            self.client = None
    
    def is_available(self):
        """Check if Secret Manager client is available"""
        return SECRET_MANAGER_AVAILABLE and self.client is not None
    
    def get_secret(self, secret_id, version_id='latest'):
        """
        Retrieve a secret from Secret Manager.
        
        Args:
            secret_id: ID of the secret
            version_id: Version of the secret (default: 'latest')
            
        Returns:
            Secret data as string or None if retrieval failed
        """
        if not self.is_available():
            logger.warning("Secret Manager client not available, cannot retrieve secret")
            return None
            
        try:
            # Build the resource name
            name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version_id}"
            
            # Access the secret version
            response = self.client.access_secret_version(request={"name": name})
            
            # Return the decoded payload
            return response.payload.data.decode('UTF-8')
        except Exception as e:
            logger.error(f"Error retrieving secret {secret_id} from Secret Manager: {str(e)}")
            return None
    
    def get_github_tokens(self):
        """
        Retrieve GitHub tokens from GCP Secret Manager.
        
        Returns:
            Dictionary mapping token scopes to lists of tokens
        """
        tokens_by_scope = {}
        
        if not self.is_available():
            logger.warning("Secret Manager client not available, cannot retrieve GitHub tokens")
            return tokens_by_scope
            
        try:
            # Get the single token first (for backward compatibility)
            single_token = self.get_secret('github-token')
            if single_token:
                logger.info("Retrieved single GitHub token from Secret Manager")
                if 'repo' not in tokens_by_scope:
                    tokens_by_scope['repo'] = []
                tokens_by_scope['repo'].append(single_token)
            
            # Get tokens by scope
            # Following scopes with common GitHub PAT permissions
            scopes = [
                'repo', 'repo_status', 'repo_deployment', 'public_repo', 'repo_invite',
                'security_events', 'workflow', 'read_org', 'admin_org', 'write_org',
                'read_user', 'manage_runners_org', 'copilot', 'manage_billing_copilot'
            ]
            
            for scope in scopes:
                # Try to get tokens for this scope
                secret_id = f"github-tokens-{scope}"
                scope_tokens_json = self.get_secret(secret_id)
                
                if scope_tokens_json:
                    try:
                        # Parse JSON array of tokens
                        scope_tokens = json.loads(scope_tokens_json)
                        if isinstance(scope_tokens, list):
                            # Use standard scope format with colons
                            standard_scope = scope.replace('_', ':')
                            logger.info(f"Retrieved {len(scope_tokens)} tokens for scope '{standard_scope}' from Secret Manager")
                            
                            if standard_scope not in tokens_by_scope:
                                tokens_by_scope[standard_scope] = []
                            tokens_by_scope[standard_scope].extend(scope_tokens)
                    except json.JSONDecodeError:
                        # If not JSON, assume it's a single token
                        standard_scope = scope.replace('_', ':')
                        logger.info(f"Retrieved single token for scope '{standard_scope}' from Secret Manager")
                        
                        if standard_scope not in tokens_by_scope:
                            tokens_by_scope[standard_scope] = []
                        tokens_by_scope[standard_scope].append(scope_tokens_json)
            
            return tokens_by_scope
            
        except Exception as e:
            logger.error(f"Error retrieving GitHub tokens from Secret Manager: {str(e)}")
            return tokens_by_scope