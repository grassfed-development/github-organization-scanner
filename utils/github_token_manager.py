import logging
import time
import requests
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger(__name__)

class GitHubTokenManager:
    """
    Manages GitHub tokens by specific permission scopes and handles token rotation with rate limit awareness.
    """
    
    # Define permission scopes needed for specific API operations
    # Based on GitHub's actual PAT scopes
    PERMISSION_MAPPING = {
        # Organization operations
        "list_organizations": ["read:org", "admin:org"],
        "org_details": ["read:org", "admin:org"],
        
        # Repository operations
        "list_repos": ["repo", "repo:status", "public_repo"],
        "repo_details": ["repo", "repo:status", "public_repo"],
        
        # Actions operations
        "list_workflows": ["workflow", "repo"],
        "workflow_details": ["workflow", "repo"],
        "list_actions": ["repo"],
        
        # Runners operations
        "list_runners": ["manage_runners:org", "admin:org"],
        
        # Security operations
        "security_alerts": ["security_events", "repo"],
        "code_scanning": ["security_events", "repo"],
        "dependabot": ["repo"],
        
        # Copilot operations
        "copilot_settings": ["copilot", "manage_billing:copilot"],
        
        # User operations
        "user_info": ["read:user"],
    }
    
    def __init__(self, tokens_by_scope: Dict[str, List[str]], base_url: str = "https://api.github.com"):
        """
        Initialize with tokens categorized by their GitHub permission scopes.
        
        Args:
            tokens_by_scope: Dictionary mapping GitHub permission scopes to lists of tokens
            base_url: Base URL for GitHub API
        """
        self.base_url = base_url
        self.tokens_by_scope = tokens_by_scope
        
        # Create a set of all unique tokens
        self.all_tokens: Set[str] = set()
        for tokens in tokens_by_scope.values():
            self.all_tokens.update(tokens)
            
        if not self.all_tokens:
            raise ValueError("At least one GitHub token must be provided")
            
        # Track rate limits for all tokens
        self.rate_limit_remaining: Dict[str, int] = {}
        self.rate_limit_reset: Dict[str, int] = {}
        
        # Initialize rate limits for all tokens
        for token in self.all_tokens:
            self.update_rate_limit(token)
    
    def get_token_for_operation(self, operation: str) -> str:
        """
        Get the best token for a specific operation based on required permission scopes.
        
        Args:
            operation: The API operation to perform (must be in PERMISSION_MAPPING)
            
        Returns:
            A GitHub token with appropriate permissions and highest rate limit
        """
        if operation not in self.PERMISSION_MAPPING:
            raise ValueError(f"Unknown operation: {operation}")
            
        # Get scopes that can perform this operation
        required_scopes = self.PERMISSION_MAPPING[operation]
        
        # Collect all tokens that have any of the required scopes
        valid_tokens = []
        for scope in required_scopes:
            if scope in self.tokens_by_scope:
                valid_tokens.extend(self.tokens_by_scope[scope])
        
        # Remove duplicates while preserving order
        unique_valid_tokens = []
        seen = set()
        for token in valid_tokens:
            if token not in seen:
                seen.add(token)
                unique_valid_tokens.append(token)
        
        if not unique_valid_tokens:
            # If no specific tokens found, fallback to any token as last resort
            logger.warning(f"No tokens found with permissions for '{operation}'. Using any available token.")
            unique_valid_tokens = list(self.all_tokens)
            
        # Sort by remaining rate limit
        sorted_tokens = sorted(
            unique_valid_tokens, 
            key=lambda token: self.rate_limit_remaining.get(token, 0), 
            reverse=True
        )
        
        # Get the token with the highest remaining limit
        best_token = sorted_tokens[0]
        
        # If best token is rate limited, try to find an alternative or wait
        if self.rate_limit_remaining.get(best_token, 0) <= 1:
            logger.warning(f"Best token for '{operation}' is rate limited. Checking alternatives.")
            
            # Update rate limits for all tokens to get fresh data
            for token in self.all_tokens:
                self.update_rate_limit(token)
                
            # Re-sort after updates
            sorted_tokens = sorted(
                unique_valid_tokens, 
                key=lambda token: self.rate_limit_remaining.get(token, 0), 
                reverse=True
            )
            
            # If all tokens are rate limited, use the one with soonest reset
            if all(self.rate_limit_remaining.get(token, 0) <= 1 for token in unique_valid_tokens):
                logger.warning(f"All tokens for '{operation}' are rate limited.")
                
                # Sort by reset time (ascending)
                sorted_by_reset = sorted(
                    unique_valid_tokens,
                    key=lambda token: self.rate_limit_reset.get(token, float('inf'))
                )
                
                best_token = sorted_by_reset[0]
                reset_time = self.rate_limit_reset.get(best_token, 0)
                wait_seconds = max(0, reset_time - int(time.time()))
                
                if wait_seconds > 0 and wait_seconds < 300:  # Only wait if less than 5 minutes
                    logger.warning(f"Waiting {wait_seconds} seconds for rate limit reset")
                    time.sleep(wait_seconds)
                    self.update_rate_limit(best_token)
            else:
                # Use the token with highest remaining limit after updates
                best_token = sorted_tokens[0]
        
        return best_token
    
    def update_rate_limit(self, token: str) -> None:
        """
        Update the rate limit information for a token.
        
        Args:
            token: GitHub token to check
        """
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(f"{self.base_url}/rate_limit", headers=headers)
            if response.status_code == 200:
                rate_data = response.json()
                core_rate = rate_data.get("resources", {}).get("core", {})
                remaining = core_rate.get("remaining", 0)
                reset_time = core_rate.get("reset", 0)
                
                self.rate_limit_remaining[token] = remaining
                self.rate_limit_reset[token] = reset_time
                
                # If rate limited, log when it will reset
                if remaining <= 1:
                    reset_seconds = reset_time - int(time.time())
                    if reset_seconds > 0:
                        logger.warning(f"Token rate limited. Reset in {reset_seconds} seconds.")
            else:
                logger.warning(f"Failed to get rate limit. Status code: {response.status_code}")
                self.rate_limit_remaining[token] = 0
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            self.rate_limit_remaining[token] = 0
    
    def update_rate_limit_from_response(self, token: str, response: requests.Response) -> None:
        """
        Update rate limit information from response headers.
        
        Args:
            token: The token used for the request
            response: The response from a GitHub API call
        """
        remaining_header = response.headers.get("X-RateLimit-Remaining")
        reset_header = response.headers.get("X-RateLimit-Reset")
        
        if remaining_header:
            self.rate_limit_remaining[token] = int(remaining_header)
        
        if reset_header:
            self.rate_limit_reset[token] = int(reset_header)