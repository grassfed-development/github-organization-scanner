import requests
import logging
import time
import re

logger = logging.getLogger(__name__)

class GitHubClient:
    def __init__(self, token, org):
        self.token = token
        self.org = org
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = 'https://api.github.com'
        logger.info(f"Initialized GitHub client for organization: {org}")
        
    def make_request(self, url, method="GET", expect_404=False, data=None):
        """Make API request with rate limit handling"""
        logger.debug(f"Requesting: {url}")
        while True:
            response = requests.request(method, url, headers=self.headers, json=data)
            
            # Check rate limits
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
        url = f'{self.base_url}/rate_limit'
        response = self.make_request(url)
        if response.status_code == 200:
            limits = response.json()
            return limits.get('resources', {}).get('core', {})
        return None
        
    def get_organization_info(self):
        """Get information about the organization"""
        url = f'{self.base_url}/orgs/{self.org}'
        response = self.make_request(url)
        if response.status_code == 200:
            return response.json()
        return None
        
    # New method for organization-level Actions configuration
    def get_org_actions_config(self):
        """Get organization-level GitHub Actions configuration"""
        url = f'{self.base_url}/orgs/{self.org}/actions'
        response = self.make_request(url, expect_404=True)
        
        if response.status_code == 200:
            return response.json()
        return {}
        
    # New methods for organization-level scanning
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