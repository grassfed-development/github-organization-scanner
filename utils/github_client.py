import requests
import logging
import time

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
        
    def make_request(self, url, method="GET", expect_404=False):
        """Make API request with rate limit handling"""
        logger.debug(f"Requesting: {url}")
        while True:
            response = requests.request(method, url, headers=self.headers)
            
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
    
    def get_all_repositories(self):
        """Get all repositories in the organization"""
        logger.info(f"Fetching repositories for {self.org}...")
        repos = []
        page = 1
        while True:
            url = f'{self.base_url}/orgs/{self.org}/repos?page={page}&per_page=100'
            response = self.make_request(url)
            
            if response.status_code != 200:
                logger.error(f"Error fetching repositories: {response.status_code}")
                break
            
            batch = response.json()
            if not batch:
                break
                
            repos.extend(batch)
            logger.info(f"Retrieved page {page}, found {len(batch)} repositories")
            page += 1
            
        logger.info(f"Total repositories found: {len(repos)}")
        return repos
    
    def get_rate_limit(self):
        """Get current rate limit status"""
        url = f'{self.base_url}/rate_limit'
        response = self.make_request(url)
        if response.status_code == 200:
            limits = response.json()
            return limits.get('resources', {}).get('core', {})
        return None