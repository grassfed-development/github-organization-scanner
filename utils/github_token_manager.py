import logging
import time
import requests
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

class GitHubTokenManager:
    """
    Manages multiple GitHub tokens to handle rate limits efficiently.
    
    This class tracks the rate limit status for each token and selects
    the best token to use for GitHub API operations based on remaining limits.
    """
    
    def __init__(self, tokens_by_scope: Dict[str, List[str]], base_url: str = "https://api.github.com"):
        """
        Initialize the token manager with tokens organized by their permission scopes.
        
        Args:
            tokens_by_scope: Dictionary mapping GitHub permission scopes to lists of tokens
            base_url: Base URL for GitHub API
        """
        self.base_url = base_url
        self.tokens_by_scope = tokens_by_scope
        
        # Flatten tokens for easier management
        self.all_tokens = []
        for scope, tokens in tokens_by_scope.items():
            for token in tokens:
                if token not in self.all_tokens:
                    self.all_tokens.append(token)
        
        # Dictionary to store rate limit info for each token
        self.rate_limits = {}
        
        # Dictionary to store last used time for each token (to prevent rapid switching)
        self.last_used = {}
        
        # Initialize rate limit info for all tokens
        self._initialize_rate_limits()
        
        # Define which scopes are required for which operations
        self.operation_to_scope_mapping = {
            # Organization operations
            "list_organizations": ["read:org", "admin:org", "write:org", "repo"],
            "org_security": ["security_events", "repo"],
            "org_dependabot": ["security_events", "repo"],
            "org_code_scanning": ["security_events", "repo"],
            "org_secret_scanning": ["security_events", "repo"],
            
            # Repository operations
            "list_repos": ["repo", "public_repo", "read:org", "admin:org", "write:org"],
            "repo_security": ["security_events", "repo"],
            
            # Workflow/Actions operations
            "list_workflows": ["workflow", "repo"],
            "list_runners": ["manage_runners:org", "workflow", "repo"]
        }
    
    def _initialize_rate_limits(self) -> None:
        """Initialize rate limit information for all tokens."""
        for token in self.all_tokens:
            try:
                # Check rate limits for this token
                self._update_rate_limit(token)
            except Exception as e:
                logger.warning(f"Failed to initialize rate limit for a token: {str(e)}")
                # Set default values to avoid excluding the token
                self.rate_limits[token] = {
                    "limit": 5000,  # Default rate limit
                    "remaining": 4500,  # Assume high remaining
                    "reset": int(time.time()) + 3600,  # Reset in an hour
                    "used": 0
                }
            
            # Initialize last used time
            self.last_used[token] = 0
    
    def _update_rate_limit(self, token: str) -> None:
        """
        Update rate limit information for a specific token.
        
        Args:
            token: GitHub token to update rate limits for
        """
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(f"{self.base_url}/rate_limit", headers=headers)
            
            if response.status_code == 200:
                rate_data = response.json().get("resources", {}).get("core", {})
                self.rate_limits[token] = {
                    "limit": rate_data.get("limit", 5000),
                    "remaining": rate_data.get("remaining", 0),
                    "reset": rate_data.get("reset", int(time.time()) + 3600),
                    "used": rate_data.get("used", 0)
                }
                logger.debug(f"Token rate limit: {self.rate_limits[token]['remaining']}/{self.rate_limits[token]['limit']} remaining")
            else:
                logger.warning(f"Failed to get rate limit for token. Status code: {response.status_code}")
        except Exception as e:
            logger.warning(f"Error updating rate limit for token: {str(e)}")
    
    def update_rate_limit_from_response(self, token: str, response: requests.Response) -> None:
        """
        Update rate limit information from an API response.
        
        Args:
            token: The GitHub token used for the request
            response: The API response containing rate limit headers
        """
        if token not in self.rate_limits:
            return
            
        try:
            # Update last used time
            self.last_used[token] = time.time()
            
            # Extract rate limit info from headers
            limit = int(response.headers.get("X-RateLimit-Limit", "5000"))
            remaining = int(response.headers.get("X-RateLimit-Remaining", "0"))
            reset = int(response.headers.get("X-RateLimit-Reset", str(int(time.time()) + 3600)))
            
            # Update the stored rate limit info
            self.rate_limits[token] = {
                "limit": limit,
                "remaining": remaining,
                "reset": reset,
                "used": limit - remaining
            }
            
            # Log warning if rate limit is getting low
            if remaining < 100:
                logger.warning(f"Rate limit for token is getting low: {remaining} remaining")
                reset_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(reset))
                logger.warning(f"Rate limit will reset at {reset_time}")
        except Exception as e:
            logger.warning(f"Error updating rate limit from response: {str(e)}")
    
    def _filter_tokens_by_operation(self, operation: str) -> List[str]:
        """
        Filter tokens that have the required scopes for a given operation.
        
        Args:
            operation: The operation to filter tokens for
            
        Returns:
            List of tokens that can perform the operation
        """
        # Get required scopes for the operation
        required_scopes = self.operation_to_scope_mapping.get(operation, ["repo"])
        
        # Collect all tokens that have at least one of the required scopes
        valid_tokens = []
        for scope in required_scopes:
            if scope in self.tokens_by_scope:
                for token in self.tokens_by_scope[scope]:
                    if token not in valid_tokens:
                        valid_tokens.append(token)
        
        # If no tokens with specific scopes, fall back to all tokens
        if not valid_tokens:
            logger.warning(f"No tokens found with required scopes for {operation}. Using all available tokens.")
            valid_tokens = self.all_tokens
            
        return valid_tokens
    
    def get_token_for_operation(self, operation: str) -> str:
        """
        Get the best token to use for a specific operation.
        
        Selects the token with the highest remaining rate limit
        from those that have the required permissions.
        
        Args:
            operation: The GitHub API operation to perform
            
        Returns:
            The best token to use
            
        Raises:
            RuntimeError: If no valid tokens are available
        """
        # Filter tokens by required scopes for the operation
        valid_tokens = self._filter_tokens_by_operation(operation)
        
        if not valid_tokens:
            raise RuntimeError("No tokens available with required permissions")
        
        # Find the token with the highest remaining limit
        best_token = None
        highest_remaining = -1
        current_time = time.time()
        
        for token in valid_tokens:
            # If token isn't in rate_limits yet, add it with default values
            if token not in self.rate_limits:
                self._update_rate_limit(token)
            
            # Get rate limit info
            rate_info = self.rate_limits.get(token, {})
            remaining = rate_info.get("remaining", 0)
            reset_time = rate_info.get("reset", 0)
            
            # Check if the token's rate limit has reset
            if current_time > reset_time and remaining < 1000:
                # Update rate limit info for this token
                self._update_rate_limit(token)
                rate_info = self.rate_limits.get(token, {})
                remaining = rate_info.get("remaining", 0)
            
            # Select the token with highest remaining limit
            if remaining > highest_remaining:
                highest_remaining = remaining
                best_token = token
        
        # If best token is about to hit rate limit, look for alternatives
        if highest_remaining < 20:
            logger.warning("All tokens are near rate limits. Checking reset times...")
            
            # Find token with the earliest reset time
            earliest_reset_token = None
            earliest_reset = float('inf')
            
            for token in valid_tokens:
                reset_time = self.rate_limits.get(token, {}).get("reset", 0)
                if reset_time < earliest_reset:
                    earliest_reset = reset_time
                    earliest_reset_token = token
            
            # If a token will reset soon, wait for it
            if earliest_reset_token and (earliest_reset - current_time) < 300:  # Within 5 minutes
                wait_time = earliest_reset - current_time + 2  # Add 2 seconds buffer
                logger.info(f"Waiting {wait_time:.1f} seconds for token rate limit to reset...")
                time.sleep(wait_time)
                
                # Update the rate limit info after waiting
                self._update_rate_limit(earliest_reset_token)
                return earliest_reset_token
                
        if best_token is None:
            raise RuntimeError("No valid token found with available rate limit")
            
        if highest_remaining < 50:
            logger.warning(f"Token has only {highest_remaining} requests remaining")
            
        return best_token
    
    def get_all_rate_limits(self) -> Dict[str, Dict[str, Any]]:
        """
        Get rate limit information for all tokens.
        
        Returns:
            Dictionary mapping token IDs to their rate limit information
        """
        # Use token IDs (last 4 chars) instead of full tokens for security
        token_rate_limits = {}
        for token in self.rate_limits:
            token_id = f"...{token[-4:]}" if len(token) >= 4 else "..."
            token_rate_limits[token_id] = self.rate_limits[token]
            
        return token_rate_limits