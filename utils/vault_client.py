import os
import logging
import hvac
from typing import Dict, List, Any, Optional
import socket
import time

logger = logging.getLogger(__name__)

class VaultClient:
    """Client for retrieving secrets from HashiCorp Vault"""
    
    def __init__(self, url=None, token=None, role_id=None, secret_id=None, mount_point='github'):
        """
        Initialize Vault client with authentication credentials.
        
        Args:
            url: Vault server URL (default: environment variable VAULT_ADDR)
            token: Vault token (default: environment variable VAULT_TOKEN)
            role_id: AppRole role ID (default: environment variable VAULT_ROLE_ID)
            secret_id: AppRole secret ID (default: environment variable VAULT_SECRET_ID)
            mount_point: The mount point for secrets (default: 'github')
        """
        self.url = url or os.environ.get('VAULT_ADDR')
        self.token = token or os.environ.get('VAULT_TOKEN')
        self.role_id = role_id or os.environ.get('VAULT_ROLE_ID')
        self.secret_id = secret_id or os.environ.get('VAULT_SECRET_ID')
        self.mount_point = mount_point
        self.client = None
        
        if not self.url:
            logger.warning("No Vault URL provided. Vault integration disabled.")
            return
            
        try:
            # Test if Vault is reachable before creating the client
            self._is_vault_reachable()
            self.client = hvac.Client(url=self.url)
            self._authenticate()
            logger.info(f"Vault client initialized for {self.url}")
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {str(e)}")
            self.client = None
    
    def _is_vault_reachable(self):
        """Check if the Vault server is reachable"""
        if not self.url:
            return False
            
        try:
            # Parse the URL to get host and port
            if self.url.startswith('http://'):
                host = self.url[7:].split('/')[0]
            elif self.url.startswith('https://'):
                host = self.url[8:].split('/')[0]
            else:
                host = self.url.split('/')[0]
                
            # Split host and port if port is specified
            if ':' in host:
                host, port_str = host.split(':')
                port = int(port_str)
            else:
                # Default ports
                port = 8200 if self.url.startswith('http') else 443
                
            # Try to connect to the host
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)  # 2 second timeout
            s.connect((host, port))
            s.close()
            return True
        except Exception as e:
            logger.warning(f"Vault server at {self.url} is not reachable: {str(e)}")
            return False

    def _authenticate(self):
        """Authenticate to Vault using the available credentials"""
        if not self.client:
            return False
            
        try:
            # Try token auth first
            if self.token:
                self.client.token = self.token
                if self.client.is_authenticated():
                    logger.info("Authenticated to Vault using token")
                    return True
                    
            # Try AppRole auth if token auth failed or no token provided
            if self.role_id and self.secret_id:
                self.client.auth.approle.login(
                    role_id=self.role_id,
                    secret_id=self.secret_id
                )
                if self.client.is_authenticated():
                    logger.info("Authenticated to Vault using AppRole")
                    return True
                    
            # Try Kubernetes auth if running in K8s
            if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token'):
                k8s_role = os.environ.get('VAULT_K8S_ROLE')
                if k8s_role:
                    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
                        jwt = f.read()
                    self.client.auth.kubernetes.login(
                        role=k8s_role,
                        jwt=jwt
                    )
                    if self.client.is_authenticated():
                        logger.info("Authenticated to Vault using Kubernetes service account")
                        return True
            
            # Check if the client is already authenticated (e.g., via environment variable)
            if self.client.is_authenticated():
                logger.info("Vault client is already authenticated")
                return True
                
            logger.warning("Failed to authenticate to Vault with any method")
            return False
            
        except Exception as e:
            logger.error(f"Error authenticating to Vault: {str(e)}")
            return False
    
    def is_available(self):
        """Check if Vault client is available and authenticated"""
        return self.client is not None and self.client.is_authenticated()
    
    def get_secret(self, path):
        """
        Retrieve a secret from Vault.
        
        Args:
            path: Path to the secret within the mount point
            
        Returns:
            Secret data or None if retrieval failed
        """
        if not self.is_available():
            logger.warning("Vault client not available, cannot retrieve secret")
            return None
            
        try:
            full_path = f"{self.mount_point}/{path}"
            response = self.client.secrets.kv.v2.read_secret_version(
                path=full_path
            )
            return response['data']['data'] if response and 'data' in response else None
        except Exception as e:
            logger.error(f"Error retrieving secret from Vault at {full_path}: {str(e)}")
            return None
    
    def get_github_tokens(self):
        """
        Retrieve GitHub tokens from Vault.
        
        Returns:
            Dictionary mapping token scopes to lists of tokens
        """
        tokens_by_scope = {}
        
        if not self.is_available():
            logger.warning("Vault client not available, cannot retrieve GitHub tokens")
            return tokens_by_scope
            
        try:
            # Get the single token first (for backward compatibility)
            single_token_data = self.get_secret('token')
            single_token = single_token_data.get('value') if single_token_data else None
            
            if single_token:
                logger.info("Retrieved single GitHub token from Vault")
                if 'repo' not in tokens_by_scope:
                    tokens_by_scope['repo'] = []
                tokens_by_scope['repo'].append(single_token)
            
            # Get scoped tokens
            # Use the convention that tokens are stored at 'github/tokens/{scope}'
            # Where each secret has multiple key-value pairs for multiple tokens
            scopes = [
                'repo', 'repo:status', 'repo_deployment', 'public_repo', 'repo:invite',
                'security_events', 'workflow', 'read:org', 'admin:org', 'write:org',
                'read:user', 'manage_runners:org', 'copilot', 'manage_billing:copilot'
            ]
            
            for scope in scopes:
                scope_path = f"tokens/{scope.replace(':', '_')}"
                scope_data = self.get_secret(scope_path)
                
                if scope_data:
                    # Each key-value pair in the secret is a token
                    scope_tokens = list(scope_data.values())
                    logger.info(f"Retrieved {len(scope_tokens)} tokens for scope '{scope}' from Vault")
                    
                    if scope not in tokens_by_scope:
                        tokens_by_scope[scope] = []
                    tokens_by_scope[scope].extend(scope_tokens)
            
            return tokens_by_scope
            
        except Exception as e:
            logger.error(f"Error retrieving GitHub tokens from Vault: {str(e)}")
            return tokens_by_scope