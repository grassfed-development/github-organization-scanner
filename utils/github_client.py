import requests
import logging
import time
import re
from typing import Dict, List, Optional, Any

from utils.github_token_manager import GitHubTokenManager

logger = logging.getLogger(__name__)

class GitHubClient:
    def __init__(self, token=None, org=None, token_manager=None, tokens_by_scope=None, base_url='https://api.github.com'):
        """
        Initialize GitHub client with either a single token or a token manager.
        
        Args:
            token: Single GitHub token (legacy support)
            org: GitHub organization name
            token_manager: Optional GitHubTokenManager instance
            tokens_by_scope: Optional dictionary mapping scopes to token lists
            base_url: Base URL for GitHub API
        """
        self.org = org
        self.base_url = base_url
        
        # Either use provided token manager or create a new one
        if token_manager:
            self.token_manager = token_manager
        elif tokens_by_scope:
            self.token_manager = GitHubTokenManager(tokens_by_scope, base_url)
        else:
            # Legacy mode with single token
            self.token = token
            self.token_manager = None
            self.headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
        logger.info(f"Initialized GitHub client for organization: {org}")
        
        # Log token mode
        if self.token_manager:
            token_count = sum(len(tokens) for tokens in self.token_manager.tokens_by_scope.values())
            logger.info(f"Using token manager with {token_count} tokens")
        else:
            logger.info("Using single token mode")
        
    def make_request(self, url, method="GET", expect_404=False, data=None):
        """Make API request with rate limit handling"""
        logger.debug(f"Requesting: {url}")
        
        # Determine operation type from URL to select appropriate token
        operation = self._determine_operation_from_url(url)
        
        while True:
            # Get headers with appropriate token
            headers = self._get_headers_for_operation(operation)
            
            # Make the request
            response = requests.request(method, url, headers=headers, json=data)
            
            # Update rate limit information if using token manager
            if self.token_manager:
                # Extract token from Authorization header
                auth_header = headers.get('Authorization', '')
                token = auth_header.replace('token ', '') if auth_header.startswith('token ') else None
                
                if token:
                    self.token_manager.update_rate_limit_from_response(token, response)
            
            # Check rate limits (using response headers)
            remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            
            if response.status_code == 200 or response.status_code == 204:
                if remaining < 10:
                    logger.warning(f"Only {remaining} API calls remaining. Being cautious.")
                return response
            elif response.status_code == 404:
                if not expect_404:
                    logger.warning(f"Resource not found (404): {url}")
                return response
            elif response.status_code == 403 and 'rate limit exceeded' in response.text.lower():
                current_time = time.time()
                sleep_time = reset_time - current_time + 5  # Add 5 seconds buffer
                
                if sleep_time > 0:
                    # If using token manager, try a different token instead of waiting
                    if self.token_manager:
                        logger.warning("Rate limit exceeded. Trying a different token...")
                        # Force token manager to update and select a different token
                        self.token_manager._update_rate_limit(headers.get('Authorization', '').replace('token ', ''))
                        continue
                    else:
                        # Single token mode - have to wait
                        logger.info(f"Rate limit exceeded. Waiting for {int(sleep_time/60)} minutes and {int(sleep_time%60)} seconds...")
                        time.sleep(sleep_time)
                        continue
            elif response.status_code == 202:
                # Sometimes GitHub returns 202 Accepted for content that's being generated
                logger.info("GitHub is processing the request. Waiting 2 seconds...")
                time.sleep(2)
                continue
            else:
                logger.error(f"Error: {response.status_code} for {url}")
                logger.error(f"Response: {response.text[:200]}...")
                return response
    
    def _determine_operation_from_url(self, url):
        """
        Determine the operation type from the URL pattern.
        
        Args:
            url: GitHub API URL
            
        Returns:
            Operation name for token selection
        """
        # Extract the path from the URL
        path = url.replace(self.base_url, '')
        
        # Check for organization-level operations
        if '/orgs/' in path:
            if '/repos' in path:
                return "list_repos"
            elif '/security-advisories' in path:
                return "org_security"
            elif '/dependabot/alerts' in path:
                return "org_dependabot"
            elif '/secret-scanning/alerts' in path:
                return "org_secret_scanning"
            elif '/code-scanning/alerts' in path:
                return "org_code_scanning"
            elif '/actions/runners' in path:
                return "list_runners"
            else:
                return "list_organizations"
        
        # Check for repository-level operations
        elif '/repos/' in path:
            if '/actions/' in path:
                return "list_workflows"
            elif '/security-and-analysis' in path or '/vulnerability-alerts' in path:
                return "repo_security"
            else:
                return "list_repos"
        
        # Check for user-level operations
        elif '/user/orgs' in path:
            return "list_organizations"
        
        # Default to repo scope for unknown operations
        return "list_repos"
    
    def _get_headers_for_operation(self, operation):
        """
        Get request headers with the appropriate token for an operation.
        
        Args:
            operation: The operation type
            
        Returns:
            Headers dictionary with authorization
        """
        if self.token_manager:
            # Get the best token for this operation
            token = self.token_manager.get_token_for_operation(operation)
            return {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }
        else:
            # Legacy mode - use the single token
            return self.headers
    
    def get_paginated_results(self, url, max_pages=None):
        """Get all paginated results for an endpoint"""
        results = []
        page = 1
        
        while True:
            # Add page parameter if it's not already in the URL
            if '?' in url:
                paginated_url = f"{url}&page={page}"
            else:
                paginated_url = f"{url}?page={page}"
                
            response = self.make_request(paginated_url)
            
            if response.status_code != 200:
                logger.error(f"Error fetching paginated results: {response.status_code}")
                break
                
            data = response.json()
            
            # Handle different response formats (array or object with items)
            if isinstance(data, list):
                batch = data
            elif isinstance(data, dict) and 'items' in data:
                batch = data['items']
            else:
                batch = []
                
            if not batch:
                break
                
            results.extend(batch)
            logger.info(f"Retrieved page {page}, found {len(batch)} items")
            
            # Check if there are more pages
            if 'Link' not in response.headers:
                break
                
            # Parse Link header to check for next page
            link_header = response.headers['Link']
            if 'rel="next"' not in link_header:
                break
                
            page += 1
            
            # Stop if we've reached the maximum number of pages
            if max_pages and page > max_pages:
                logger.info(f"Reached maximum number of pages ({max_pages})")
                break
                
        logger.info(f"Total items found: {len(results)}")
        return results
    
    def get_all_repositories(self):
        """Get all repositories in the organization"""
        logger.info(f"Fetching repositories for {self.org}...")
        url = f'{self.base_url}/orgs/{self.org}/repos?per_page=100'
        return self.get_paginated_results(url)
    
    def get_rate_limit(self):
        """Get current rate limit status"""
        # If using token manager, get all rate limits
        if self.token_manager:
            limits = self.token_manager.get_all_rate_limits()
            # Return the highest remaining limit
            highest_remaining = 0
            best_limit = None
            
            for token_id, limit_info in limits.items():
                if limit_info['remaining'] > highest_remaining:
                    highest_remaining = limit_info['remaining']
                    best_limit = limit_info
            
            return best_limit
        else:
            # Legacy mode - check single token
            url = f'{self.base_url}/rate_limit'
            response = self.make_request(url)
            if response.status_code == 200:
                limits = response.json()
                return limits.get('resources', {}).get('core', {})
            return None
    
    # All the other methods remain the same
    def get_organization_info(self):
        """Get information about the organization"""
        url = f'{self.base_url}/orgs/{self.org}'
        response = self.make_request(url)
        if response.status_code == 200:
            return response.json()
        return None
        
    def get_org_actions_config(self):
        """Get organization-level GitHub Actions configuration"""
        url = f'{self.base_url}/orgs/{self.org}/actions'
        response = self.make_request(url, expect_404=True)
        
        if response.status_code == 200:
            return response.json()
        return {}
        
    def get_org_security_features(self):
        """Get organization-level security features"""
        url = f'{self.base_url}/orgs/{self.org}/security-and-analysis'
        response = self.make_request(url, expect_404=True)
        
        if response.status_code == 200:
            return response.json()
        return {}
        
    def get_repository_security_features(self, repo_name):
        """Get security features for a specific repository"""
        url = f'{self.base_url}/repos/{self.org}/{repo_name}/security-and-analysis'
        response = self.make_request(url, expect_404=True)
        
        if response.status_code == 200:
            return response.json()
        return {}
        
    def get_repository_contents(self, repo_name, path):
        """Get contents of a file or directory in a repository"""
        url = f'{self.base_url}/repos/{self.org}/{repo_name}/contents/{path}'
        response = self.make_request(url, expect_404=True)
        
        if response.status_code == 200:
            return response.json()
        return {}
        
    def get_org_dependabot_alerts(self):
        """Get all Dependabot alerts for the organization"""
        url = f'{self.base_url}/orgs/{self.org}/dependabot/alerts?state=open&per_page=100'
        return self.get_paginated_results(url)
        
    def get_org_secret_scanning_alerts(self):
        """Get all secret scanning alerts for the organization"""
        url = f'{self.base_url}/orgs/{self.org}/secret-scanning/alerts?state=open&per_page=100'
        return self.get_paginated_results(url)
    
    def get_org_code_scanning_alerts(self):
        """Get all code scanning alerts for the organization"""
        url = f'{self.base_url}/orgs/{self.org}/code-scanning/alerts?state=open&per_page=100'
        return self.get_paginated_results(url)
    
    def get_org_runners(self):
        """Get all GitHub Actions runners for the organization"""
        url = f'{self.base_url}/orgs/{self.org}/actions/runners'
        response = self.make_request(url)
        
        if response.status_code == 200:
            return response.json().get('runners', [])
        return []