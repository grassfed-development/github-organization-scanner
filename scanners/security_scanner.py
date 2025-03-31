import logging
from collections import Counter
from datetime import datetime
from typing import Dict, Any, List, Optional

from utils.github_client import GitHubClient
from scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class GitHubSecurityAnalyzer(BaseScanner):
    """
    Improved security scanner that uses organization-level endpoints
    instead of making individual repository API calls when possible.
    """
    
    def __init__(self, token: str, org: str, storage_client=None):
        # Initialize GitHub client
        github_client = GitHubClient(token, org)
        super().__init__(github_client, storage_client)
    
    def scan(self) -> Dict[str, Any]:
        """Analyze security status across all repositories using org-level APIs where possible"""
        # Get all repositories
        logger.info(f"Fetching repositories for {self.org}...")
        repos = self.github_client.get_all_repositories()
        
        # Check rate limits before starting major operations
        rate_limit = self.github_client.get_rate_limit()
        logger.info(f"API calls remaining: {rate_limit.get('remaining', 0)}")
        
        # Initialize data structures
        security_data = {
            'org': self.org,
            'total_repositories': len(repos),
            'security_features': {
                'advanced_security_enabled': 0,
                'secret_scanning_enabled': 0,
                'secret_scanning_push_protection_enabled': 0,
                'vulnerability_alerts_enabled': 0,
                'automated_security_fixes_enabled': 0
            },
            'alert_counts': {
                'repositories_with_secret_alerts': 0,
                'repositories_with_code_alerts': 0, 
                'repositories_with_dependabot_alerts': 0,
                'total_secret_scanning_alerts': 0,
                'total_code_scanning_alerts': 0,
                'total_dependabot_alerts': 0
            },
            'repositories': []
        }
        
        # Step 1: Fetch all organization-level alerts
        # This is more efficient than making individual repo API calls
        logger.info(f"Fetching organization-level alerts for {self.org}...")
        
        # Get organization-level security features
        org_security_features = self.github_client.get_org_security_features()
        logger.info(f"Retrieved organization-level security features")
        
        # Get all dependabot alerts at organization level
        logger.info(f"Fetching organization-level Dependabot alerts...")
        dependabot_alerts = self.github_client.get_org_dependabot_alerts()
        logger.info(f"Retrieved {len(dependabot_alerts)} organization-level Dependabot alerts")
        
        # Get all secret scanning alerts at organization level
        logger.info(f"Fetching organization-level Secret Scanning alerts...")
        secret_alerts = self.github_client.get_org_secret_scanning_alerts()
        logger.info(f"Retrieved {len(secret_alerts)} organization-level Secret Scanning alerts")
        
        # Get all code scanning alerts at organization level
        logger.info(f"Fetching organization-level Code Scanning alerts...")
        code_alerts = self.github_client.get_org_code_scanning_alerts()
        logger.info(f"Retrieved {len(code_alerts)} organization-level Code Scanning alerts")
        
        # Step 2: Process alerts and create repository mappings
        # Create dictionaries for quick lookups by repository
        repo_to_dependabot_alerts = {}
        repo_to_secret_alerts = {}
        repo_to_code_alerts = {}
        
        # Process dependabot alerts by repository
        for alert in dependabot_alerts:
            repo_name = alert.get('repository', {}).get('name')
            if repo_name:
                if repo_name not in repo_to_dependabot_alerts:
                    repo_to_dependabot_alerts[repo_name] = []
                repo_to_dependabot_alerts[repo_name].append(alert)
        
        # Process secret scanning alerts by repository
        for alert in secret_alerts:
            repo_name = alert.get('repository', {}).get('name')
            if repo_name:
                if repo_name not in repo_to_secret_alerts:
                    repo_to_secret_alerts[repo_name] = []
                repo_to_secret_alerts[repo_name].append(alert)
        
        # Process code scanning alerts by repository
        for alert in code_alerts:
            repo_name = alert.get('repository', {}).get('name')
            if repo_name:
                if repo_name not in repo_to_code_alerts:
                    repo_to_code_alerts[repo_name] = []
                repo_to_code_alerts[repo_name].append(alert)
        
        # Update alert counts
        security_data['alert_counts']['repositories_with_secret_alerts'] = len(repo_to_secret_alerts)
        security_data['alert_counts']['repositories_with_code_alerts'] = len(repo_to_code_alerts)
        security_data['alert_counts']['repositories_with_dependabot_alerts'] = len(repo_to_dependabot_alerts)
        security_data['alert_counts']['total_secret_scanning_alerts'] = len(secret_alerts)
        security_data['alert_counts']['total_code_scanning_alerts'] = len(code_alerts)
        security_data['alert_counts']['total_dependabot_alerts'] = len(dependabot_alerts)
        
        # Counters for aggregation
        secret_types = Counter()
        code_alert_rules = Counter()
        dependabot_packages = Counter()
        dependabot_severities = Counter()
        
        # Process alerts for reporting
        for alert in secret_alerts:
            secret_types[alert.get('secret_type', 'unknown')] += 1
            
        for alert in code_alerts:
            rule = alert.get('rule', {}).get('id', 'unknown')
            code_alert_rules[rule] += 1
            
        for alert in dependabot_alerts:
            package = alert.get('dependency', {}).get('package', {}).get('name', 'unknown')
            severity = alert.get('security_advisory', {}).get('severity', 'unknown')
            dependabot_packages[package] += 1
            dependabot_severities[severity] += 1
        
        # Step 3: Process repositories
        # Since we can't get all security features at the org level,
        # we still need to make some per-repository API calls
        for repo in repos:
            repo_name = repo['name']
            logger.info(f"Processing repository {repo_name}... ({repos.index(repo) + 1}/{len(repos)})")
            
            repo_data = {
                'name': repo_name,
                'url': repo['html_url'],
                'private': repo['private'],
                'security_features': {},
                'alerts': {
                    'secret_scanning': repo_to_secret_alerts.get(repo_name, []),
                    'code_scanning': repo_to_code_alerts.get(repo_name, []),
                    'dependabot': repo_to_dependabot_alerts.get(repo_name, [])
                }
            }
            
            # Check individual repository security features
            # We still need to do this per repo, as organization-level endpoint doesn't
            # give us the full picture for each repository
            security_features = self.github_client.get_repository_security_features(repo_name)
            
            # Add feature status to repo data
            repo_data['security_features'] = {
                'advanced_security': security_features.get('advanced_security', {}).get('status') == 'enabled',
                'secret_scanning': security_features.get('secret_scanning', {}).get('status') == 'enabled',
                'secret_scanning_push_protection': security_features.get('secret_scanning_push_protection', {}).get('status') == 'enabled',
                'vulnerability_alerts': bool(repo_to_dependabot_alerts.get(repo_name)),  # Infer from alerts presence
                'automated_security_fixes': 'dependabot.yml' in self.github_client.get_repository_contents(repo_name, '.github')  # Check for dependabot config
            }
            
            # Update org-wide counters
            if repo_data['security_features']['advanced_security']:
                security_data['security_features']['advanced_security_enabled'] += 1
            if repo_data['security_features']['secret_scanning']:
                security_data['security_features']['secret_scanning_enabled'] += 1
            if repo_data['security_features']['secret_scanning_push_protection']:
                security_data['security_features']['secret_scanning_push_protection_enabled'] += 1
            if repo_data['security_features']['vulnerability_alerts']:
                security_data['security_features']['vulnerability_alerts_enabled'] += 1
            if repo_data['security_features']['automated_security_fixes']:
                security_data['security_features']['automated_security_fixes_enabled'] += 1
            
            # Add to repository list
            security_data['repositories'].append(repo_data)
        
        # Add aggregated data
        security_data['top_vulnerabilities'] = {
            'secret_types': dict(secret_types.most_common(20)),
            'code_rules': dict(code_alert_rules.most_common(20)),
            'dependabot_packages': dict(dependabot_packages.most_common(20)),
            'dependabot_severities': dict(dependabot_severities)
        }
        
        # Calculate percentages
        total_repos = security_data['total_repositories']
        if total_repos > 0:
            security_data['security_features']['advanced_security_percentage'] = round(
                (security_data['security_features']['advanced_security_enabled'] / total_repos) * 100, 2
            )
            security_data['security_features']['secret_scanning_percentage'] = round(
                (security_data['security_features']['secret_scanning_enabled'] / total_repos) * 100, 2
            )
            security_data['security_features']['secret_scanning_push_protection_percentage'] = round(
                (security_data['security_features']['secret_scanning_push_protection_enabled'] / total_repos) * 100, 2
            )
            security_data['security_features']['vulnerability_alerts_percentage'] = round(
                (security_data['security_features']['vulnerability_alerts_enabled'] / total_repos) * 100, 2
            )
            security_data['security_features']['automated_security_fixes_percentage'] = round(
                (security_data['security_features']['automated_security_fixes_enabled'] / total_repos) * 100, 2
            )
        
        return security_data
        
    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of GitHub security status"""
        logger.info("Analyzing GitHub security status...")
        data = self.scan()
        
        # Generate basic report
        logger.info("=" * 50)
        logger.info(f"GitHub Security Status Report for {self.org}")
        logger.info("=" * 50)
        
        logger.info("\nSecurity Features:")
        logger.info(f"  Total repositories: {data['total_repositories']}")
        logger.info(f"  Advanced Security enabled: {data['security_features']['advanced_security_enabled']} ({data['security_features'].get('advanced_security_percentage', 0)}%)")
        logger.info(f"  Secret Scanning enabled: {data['security_features']['secret_scanning_enabled']} ({data['security_features'].get('secret_scanning_percentage', 0)}%)")
        logger.info(f"  Secret Scanning Push Protection enabled: {data['security_features']['secret_scanning_push_protection_enabled']} ({data['security_features'].get('secret_scanning_push_protection_percentage', 0)}%)")
        logger.info(f"  Vulnerability Alerts enabled: {data['security_features']['vulnerability_alerts_enabled']} ({data['security_features'].get('vulnerability_alerts_percentage', 0)}%)")
        logger.info(f"  Automated Security Fixes enabled: {data['security_features']['automated_security_fixes_enabled']} ({data['security_features'].get('automated_security_fixes_percentage', 0)}%)")
        
        logger.info("\nAlert Summary:")
        logger.info(f"  Repositories with Secret Scanning alerts: {data['alert_counts']['repositories_with_secret_alerts']}")
        logger.info(f"  Repositories with Code Scanning alerts: {data['alert_counts']['repositories_with_code_alerts']}")
        logger.info(f"  Repositories with Dependabot alerts: {data['alert_counts']['repositories_with_dependabot_alerts']}")
        logger.info(f"  Total Secret Scanning alerts: {data['alert_counts']['total_secret_scanning_alerts']}")
        logger.info(f"  Total Code Scanning alerts: {data['alert_counts']['total_code_scanning_alerts']}")
        logger.info(f"  Total Dependabot alerts: {data['alert_counts']['total_dependabot_alerts']}")
        
        if data['top_vulnerabilities']['secret_types']:
            logger.info("\nTop Secret Types:")
            for secret_type, count in data['top_vulnerabilities']['secret_types'].items():
                logger.info(f"  {secret_type}: {count}")
        
        if data['top_vulnerabilities']['code_rules']:
            logger.info("\nTop Code Scanning Rules:")
            for rule, count in data['top_vulnerabilities']['code_rules'].items():
                logger.info(f"  {rule}: {count}")
        
        if data['top_vulnerabilities']['dependabot_packages']:
            logger.info("\nTop Vulnerable Packages:")
            for package, count in data['top_vulnerabilities']['dependabot_packages'].items():
                logger.info(f"  {package}: {count}")
        
        if data['top_vulnerabilities']['dependabot_severities']:
            logger.info("\nDependabot Alert Severities:")
            for severity, count in data['top_vulnerabilities']['dependabot_severities'].items():
                logger.info(f"  {severity}: {count}")
        
        # Save report
        data = self.save_report(data)
        logger.info(f"Detailed report saved to {data['report_file']['local_path']}")
        if data['report_file']['gcs_path']:
            logger.info(f"Report uploaded to {data['report_file']['gcs_path']}")
            
        return data