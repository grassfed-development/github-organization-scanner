import logging
from collections import Counter
from datetime import datetime

from utils.github_client import GitHubClient
from scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class GitHubSecurityAnalyzer(BaseScanner):
    def __init__(self, token, org, storage_client=None):
        # Initialize GitHub client
        github_client = GitHubClient(token, org)
        super().__init__(github_client, storage_client)
    
    def check_security_features(self, repo_name):
        """Check security features enabled for a repository"""
        url = f'{self.github_client.base_url}/repos/{self.org}/{repo_name}/security-and-analysis'
        response = self.github_client.make_request(url, expect_404=True)
        
        if response.status_code != 200:
            return {
                "advanced_security": {"status": "disabled"},
                "secret_scanning": {"status": "disabled"},
                "secret_scanning_push_protection": {"status": "disabled"}
            }
            
        return response.json()

    def check_vulnerability_alerts(self, repo_name):
        """Check if vulnerability alerts are enabled"""
        url = f'{self.github_client.base_url}/repos/{self.org}/{repo_name}/vulnerability-alerts'
        response = self.github_client.make_request(url, expect_404=True)
        
        # 204 means enabled, 404 means disabled
        return response.status_code == 204

    def check_automated_security_fixes(self, repo_name):
        """Check if automated security fixes are enabled"""
        url = f'{self.github_client.base_url}/repos/{self.org}/{repo_name}/automated-security-fixes'
        response = self.github_client.make_request(url, expect_404=True)
        
        if response.status_code != 200:
            return False
            
        return response.json().get('enabled', False)

    def get_secret_scanning_alerts(self, repo_name):
        """Get secret scanning alerts for a repository"""
        url = f'{self.github_client.base_url}/repos/{self.org}/{repo_name}/secret-scanning/alerts?state=open&per_page=100'
        response = self.github_client.make_request(url, expect_404=True)
        
        if response.status_code != 200:
            return []
            
        return response.json()

    def get_code_scanning_alerts(self, repo_name):
        """Get code scanning alerts for a repository"""
        url = f'{self.github_client.base_url}/repos/{self.org}/{repo_name}/code-scanning/alerts?state=open&per_page=100'
        response = self.github_client.make_request(url, expect_404=True)
        
        if response.status_code != 200:
            return []
            
        return response.json()

    def get_dependabot_alerts(self, repo_name):
        """Get Dependabot alerts for a repository"""
        url = f'{self.github_client.base_url}/repos/{self.org}/{repo_name}/dependabot/alerts?state=open&per_page=100'
        response = self.github_client.make_request(url, expect_404=True)
        
        if response.status_code != 200:
            return []
            
        return response.json()

    def scan(self):
        """Analyze security status across all repositories"""
        repos = self.github_client.get_all_repositories()
        
        # Check rate limits before starting
        rate_limit = self.github_client.get_rate_limit()
        if rate_limit:
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
        
        # Counters for aggregation
        secret_types = Counter()
        code_alert_rules = Counter()
        dependabot_packages = Counter()
        dependabot_severities = Counter()
        
        for repo in repos:
            repo_name = repo['name']
            logger.info(f"Analyzing security for {repo_name}... ({repos.index(repo) + 1}/{len(repos)})")
            
            repo_data = {
                'name': repo_name,
                'url': repo['html_url'],
                'private': repo['private'],
                'security_features': {},
                'alerts': {
                    'secret_scanning': [],
                    'code_scanning': [],
                    'dependabot': []
                }
            }
            
            # Check security features
            security_features = self.check_security_features(repo_name)
            
            # Add feature status to repo data
            repo_data['security_features'] = {
                'advanced_security': security_features.get('advanced_security', {}).get('status') == 'enabled',
                'secret_scanning': security_features.get('secret_scanning', {}).get('status') == 'enabled',
                'secret_scanning_push_protection': security_features.get('secret_scanning_push_protection', {}).get('status') == 'enabled',
                'vulnerability_alerts': self.check_vulnerability_alerts(repo_name),
                'automated_security_fixes': self.check_automated_security_fixes(repo_name)
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
            
            # Get alerts if features are enabled
            if repo_data['security_features']['secret_scanning']:
                secret_alerts = self.get_secret_scanning_alerts(repo_name)
                repo_data['alerts']['secret_scanning'] = secret_alerts
                
                if secret_alerts:
                    security_data['alert_counts']['repositories_with_secret_alerts'] += 1
                    security_data['alert_counts']['total_secret_scanning_alerts'] += len(secret_alerts)
                    
                    # Count secret types
                    for alert in secret_alerts:
                        secret_types[alert.get('secret_type', 'unknown')] += 1
            
            if repo_data['security_features']['advanced_security']:
                code_alerts = self.get_code_scanning_alerts(repo_name)
                repo_data['alerts']['code_scanning'] = code_alerts
                
                if code_alerts:
                    security_data['alert_counts']['repositories_with_code_alerts'] += 1
                    security_data['alert_counts']['total_code_scanning_alerts'] += len(code_alerts)
                    
                    # Count rule types
                    for alert in code_alerts:
                        rule = alert.get('rule', {}).get('id', 'unknown')
                        code_alert_rules[rule] += 1
            
            if repo_data['security_features']['vulnerability_alerts']:
                dependabot_alerts = self.get_dependabot_alerts(repo_name)
                repo_data['alerts']['dependabot'] = dependabot_alerts
                
                if dependabot_alerts:
                    security_data['alert_counts']['repositories_with_dependabot_alerts'] += 1
                    security_data['alert_counts']['total_dependabot_alerts'] += len(dependabot_alerts)
                    
                    # Count package and severity
                    for alert in dependabot_alerts:
                        package = alert.get('dependency', {}).get('package', {}).get('name', 'unknown')
                        severity = alert.get('security_advisory', {}).get('severity', 'unknown')
                        dependabot_packages[package] += 1
                        dependabot_severities[severity] += 1
            
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
        
    def generate_report(self):
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