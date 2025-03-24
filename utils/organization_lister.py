import logging
from utils.github_client import GitHubClient

logger = logging.getLogger(__name__)

class GitHubOrgLister:
    def __init__(self, token):
        self.token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = 'https://api.github.com'
        self.github_client = GitHubClient(token, None)
        
    def list_user_organizations(self):
        """List organizations that the authenticated user belongs to"""
        url = f'{self.base_url}/user/orgs'
        response = self.github_client.make_request(url)
        
        if response.status_code != 200:
            logger.error(f"Error fetching user organizations: {response.status_code}")
            return []
            
        orgs = response.json()
        logger.info(f"Found {len(orgs)} organizations for authenticated user")
        return orgs
    
    def list_all_organizations(self, since_id=0):
        """List all GitHub organizations (public)
        
        Note: This is a paginated request that returns public organizations
        in the order they were created. It requires no special permissions.
        """
        all_orgs = []
        current_id = since_id
        
        while True:
            url = f'{self.base_url}/organizations?since={current_id}'
            response = self.github_client.make_request(url)
            
            if response.status_code != 200:
                logger.error(f"Error fetching organizations: {response.status_code}")
                break
                
            orgs = response.json()
            if not orgs:
                break
                
            all_orgs.extend(orgs)
            logger.info(f"Retrieved {len(orgs)} organizations")
            
            # Get ID of the last organization for pagination
            current_id = orgs[-1]['id']
            
            # For testing or demo purposes, limit to 1000 organizations
            if len(all_orgs) >= 1000:
                logger.info("Reached 1000 organizations limit, stopping")
                break
                
        logger.info(f"Found {len(all_orgs)} public organizations in total")
        return all_orgs
    
    def list_enterprise_organizations(self, enterprise_slug):
        """List organizations in an enterprise
        
        Note: This requires enterprise admin permissions
        """
        url = f'{self.base_url}/enterprises/{enterprise_slug}/organizations'
        response = self.github_client.make_request(url)
        
        if response.status_code != 200:
            logger.error(f"Error fetching enterprise organizations: {response.status_code}")
            return []
            
        orgs = response.json().get('organizations', [])
        logger.info(f"Found {len(orgs)} organizations in enterprise {enterprise_slug}")
        return orgs