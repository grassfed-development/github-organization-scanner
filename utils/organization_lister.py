import logging
import requests
from typing import List, Dict, Any, Optional

from utils.github_token_manager import GitHubTokenManager

logger = logging.getLogger(__name__)

class GitHubOrgLister:
    """Class to list GitHub organizations and repositories with permission-scoped tokens."""
    
    def __init__(self, 
                 tokens_by_scope: Optional[Dict[str, List[str]]] = None, 
                 single_token: Optional[str] = None, 
                 base_url: str = "https://api.github.com"):
        """
        Initialize with GitHub tokens categorized by their permission scopes.
        
        Args:
            tokens_by_scope: Dictionary mapping GitHub permission scopes to lists of tokens
            single_token: A single GitHub token (for backward compatibility)
            base_url: Base URL for GitHub API
        """
        self.base_url = base_url
        
        # Handle backward compatibility with single token
        if tokens_by_scope is None:
            tokens_by_scope = {}
        
        if single_token and not tokens_by_scope:
            # If only single_token provided, add it to repo scope (full access assumption)
            tokens_by_scope = {"repo": [single_token]}
        elif single_token:
            # If both provided, add single_token to repo scope if not already present
            repo_tokens = tokens_by_scope.get("repo", [])
            if single_token not in repo_tokens:
                if "repo" not in tokens_by_scope:
                    tokens_by_scope["repo"] = []
                tokens_by_scope["repo"].append(single_token)
        
        # Initialize token manager
        self.token_manager = GitHubTokenManager(tokens_by_scope, base_url)
    
    def list_user_organizations(self) -> List[Dict[str, Any]]:
        """
        List all organizations the authenticated user has access to.
        
        Returns:
            List of organizations with their details
        """
        all_orgs = []
        page = 1
        per_page = 100
        
        while True:
            # Get the appropriate token for this operation
            token = self.token_manager.get_token_for_operation("list_organizations")
            
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            try:
                response = requests.get(
                    f"{self.base_url}/user/orgs",
                    headers=headers,
                    params={"page": page, "per_page": per_page}
                )
                
                # Update rate limit info after request
                self.token_manager.update_rate_limit_from_response(token, response)
                
                if response.status_code == 200:
                    orgs_page = response.json()
                    if not orgs_page:
                        break
                        
                    all_orgs.extend(orgs_page)
                    
                    # Check if we need to get the next page
                    if len(orgs_page) < per_page:
                        break
                        
                    page += 1
                else:
                    logger.error(f"Failed to list organizations. Status code: {response.status_code}")
                    logger.error(f"Response body: {response.text}")
                    break
            except Exception as e:
                logger.error(f"Error listing organizations: {str(e)}")
                break
        
        logger.info(f"Found {len(all_orgs)} organizations")
        return all_orgs

    def get_organization_repos(self, org_name: str) -> List[Dict[str, Any]]:
        """
        Get all repositories for a specific organization.
        
        Args:
            org_name: Name of the organization
            
        Returns:
            List of repositories with their details
        """
        all_repos = []
        page = 1
        per_page = 100
        
        while True:
            # Get the appropriate token for this operation
            token = self.token_manager.get_token_for_operation("list_repos")
            
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            try:
                response = requests.get(
                    f"{self.base_url}/orgs/{org_name}/repos",
                    headers=headers,
                    params={"page": page, "per_page": per_page, "type": "all"}
                )
                
                # Update rate limit info after request
                self.token_manager.update_rate_limit_from_response(token, response)
                
                if response.status_code == 200:
                    repos_page = response.json()
                    if not repos_page:
                        break
                        
                    all_repos.extend(repos_page)
                    
                    # Check if we need to get the next page
                    if len(repos_page) < per_page:
                        break
                        
                    page += 1
                else:
                    logger.error(f"Failed to list repositories for {org_name}. Status code: {response.status_code}")
                    logger.error(f"Response body: {response.text}")
                    break
            except Exception as e:
                logger.error(f"Error listing repositories: {str(e)}")
                break
        
        logger.info(f"Found {len(all_repos)} repositories for organization {org_name}")
        return all_repos
    
    def get_workflow_runs(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """
        Get workflow runs for a repository.
        
        Args:
            owner: Repository owner (user or organization)
            repo: Repository name
            
        Returns:
            List of workflow runs
        """
        # Get token with workflow or repo permissions
        token = self.token_manager.get_token_for_operation("list_workflows")
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/repos/{owner}/{repo}/actions/runs",
                headers=headers
            )
            
            # Update rate limit info
            self.token_manager.update_rate_limit_from_response(token, response)
            
            if response.status_code == 200:
                return response.json().get("workflow_runs", [])
            else:
                logger.error(f"Failed to get workflow runs. Status code: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error getting workflow runs: {str(e)}")
            return []
    
    def get_security_alerts(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """
        Get security alerts for a repository.
        
        Args:
            owner: Repository owner (user or organization)
            repo: Repository name
            
        Returns:
            List of security alerts
        """
        # Get token with security_events permission
        token = self.token_manager.get_token_for_operation("security_alerts")
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/repos/{owner}/{repo}/vulnerability-alerts",
                headers=headers
            )
            
            # Update rate limit info
            self.token_manager.update_rate_limit_from_response(token, response)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get security alerts. Status code: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error getting security alerts: {str(e)}")
            return []
    
    def get_organization_runners(self, org: str) -> List[Dict[str, Any]]:
        """
        Get GitHub Actions runners for an organization.
        
        Args:
            org: Organization name
            
        Returns:
            List of runners
        """
        # Get token with manage_runners:org permission
        token = self.token_manager.get_token_for_operation("list_runners")
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/orgs/{org}/actions/runners",
                headers=headers
            )
            
            # Update rate limit info
            self.token_manager.update_rate_limit_from_response(token, response)
            
            if response.status_code == 200:
                return response.json().get("runners", [])
            else:
                logger.error(f"Failed to get organization runners. Status code: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error getting organization runners: {str(e)}")
            return []