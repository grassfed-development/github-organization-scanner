import os
import json
import logging
import argparse
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

# Import scanner components
from utils.github_client import GitHubClient
from utils.github_token_manager import GitHubTokenManager
from utils.vault_client import VaultClient
from scanners.actions_scanner import GitHubActionsAnalyzer
from scanners.security_scanner import GitHubSecurityAnalyzer
from storage.gcs_client import GCSClient
from utils.logger import setup_logger
from config import GITHUB_TOKENS_BY_SCOPE, GITHUB_TOKEN, ENV, vault_client

app = Flask(__name__)

# Default configuration
DEFAULT_CONFIG = {
    'LOG_LEVEL': os.environ.get('LOG_LEVEL', 'INFO'),
    'GITHUB_TOKEN': GITHUB_TOKEN,
    'GITHUB_TOKENS_BY_SCOPE': GITHUB_TOKENS_BY_SCOPE,
    'GITHUB_ORG': os.environ.get('GITHUB_ORG'),
    'GCS_BUCKET': os.environ.get('BUCKET_NAME'),
    'BASE_URL': os.environ.get('BASE_URL', 'https://api.github.com'),
    'DEBUG': os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't'),
    'PORT': int(os.environ.get('PORT', 8080)),
    'REPORTS_DIR': os.environ.get('REPORTS_DIR', 'reports'),
    'REPO_LIMIT': int(os.environ.get('REPO_LIMIT', 0)),  # 0 means no limit
    'ENV': ENV,
    'VAULT_ENABLED': vault_client is not None and vault_client.is_available()
}

# Check if token is available
if not DEFAULT_CONFIG['GITHUB_TOKEN'] and not DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE']:
    print("ERROR - Missing required GitHub token configuration")
    print("GitHub tokens are required. Configure one of the following:")
    print("")
    print("1. HashiCorp Vault (recommended):")
    print("   - VAULT_ADDR: URL of the Vault server")
    print("   - Authentication: VAULT_TOKEN, VAULT_ROLE_ID/VAULT_SECRET_ID, or Kubernetes auth")
    print("   - VAULT_GITHUB_MOUNT: The mount point for GitHub tokens (default: github)")
    print("")
    print("2. Environment Variables (fallback):")
    print("   - GITHUB_TOKEN: Single GitHub token")
    print("   - Scoped tokens: GITHUB_TOKENS_REPO, GITHUB_TOKENS_SECURITY_EVENTS, etc.")
    print("")
    print("Current environment variables:", list(filter(lambda k: not k.startswith('GITHUB_TOKEN'), os.environ.keys())))
    print("Current working directory:", os.getcwd())
    
    # Check if .env file exists
    env_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_path):
        print(".env file exists. Showing first few non-sensitive lines:")
        with open(env_path, 'r') as f:
            for line in f:
                if not line.strip().startswith(('GITHUB_TOKEN', 'VAULT_TOKEN', 'VAULT_SECRET_ID')):
                    print(line.strip())
                else:
                    print(line.split('=')[0] + "=***************")
    else:
        print(".env file not found!")

# Configure logging
setup_logger(DEFAULT_CONFIG['LOG_LEVEL'])
logger = logging.getLogger(__name__)

# Initialize token manager if we have tokens by scope
token_manager = None
if DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE']:
    token_manager = GitHubTokenManager(
        DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE'], 
        DEFAULT_CONFIG['BASE_URL']
    )
    logger.info(f"Token manager initialized with tokens for {len(DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE'])} scopes")
    # Log token count by scope
    for scope, tokens in DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE'].items():
        logger.info(f"  {scope}: {len(tokens)} tokens")

# Log environment information
logger.info(f"Running in {DEFAULT_CONFIG['ENV']} environment")
logger.info(f"Vault integration: {'Enabled' if DEFAULT_CONFIG['VAULT_ENABLED'] else 'Disabled'}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    token_source = "vault" if DEFAULT_CONFIG['VAULT_ENABLED'] else "environment"
    return jsonify({
        "status": "healthy", 
        "environment": DEFAULT_CONFIG['ENV'],
        "token_source": token_source,
        "vault_available": DEFAULT_CONFIG['VAULT_ENABLED'],
        "tokens_available": bool(DEFAULT_CONFIG['GITHUB_TOKEN']) or bool(DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE'])
    }), 200

@app.route('/scan/actions', methods=['POST'])
def scan_actions():
    """Endpoint to scan GitHub Actions"""
    data = request.get_json() or {}
    
    # Get parameters from request or use defaults
    token = data.get('token') or DEFAULT_CONFIG['GITHUB_TOKEN']
    org = data.get('org') or DEFAULT_CONFIG['GITHUB_ORG']
    bucket_name = data.get('bucket') or DEFAULT_CONFIG['GCS_BUCKET']
    repo_limit = data.get('repo_limit', DEFAULT_CONFIG['REPO_LIMIT'])
    
    if not org or (not token and not token_manager):
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize storage client
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Run scanner
        logger.info(f"Starting Actions scan for {org}...")
        if repo_limit > 0:
            logger.info(f"Repository limit set to {repo_limit}")
            
        # Create GitHub client with token manager if available
        if token_manager:
            github_client = GitHubClient(org=org, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
            analyzer = GitHubActionsAnalyzer(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
        else:
            # Legacy single token mode
            analyzer = GitHubActionsAnalyzer(token, org, storage_client, repo_limit)
            
        report = analyzer.generate_report()
        
        return jsonify({
            "status": "success",
            "organization": org,
            "repo_limit_applied": repo_limit if repo_limit > 0 else None,
            "report_file": report.get("report_file"),
            "summary": {
                "total_repositories": report.get("total_repositories"),
                "archived_repositories": report.get("archived_repositories", 0),
                "repositories_with_workflows": report.get("repositories_with_workflows"),
                "total_actions_used": report.get("total_actions_used"),
                "unique_actions_used": report.get("unique_actions_used")
            }
        }), 200
    except Exception as e:
        logger.exception(f"Error scanning actions: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/scan/security', methods=['POST'])
def scan_security():
    """Endpoint to scan GitHub Security features"""
    data = request.get_json() or {}
    
    # Get parameters from request or use defaults
    token = data.get('token') or DEFAULT_CONFIG['GITHUB_TOKEN']
    org = data.get('org') or DEFAULT_CONFIG['GITHUB_ORG']
    bucket_name = data.get('bucket') or DEFAULT_CONFIG['GCS_BUCKET']
    repo_limit = data.get('repo_limit', DEFAULT_CONFIG['REPO_LIMIT'])
    
    if not org or (not token and not token_manager):
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize storage client
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Run scanner
        logger.info(f"Starting Security scan for {org}...")
        if repo_limit > 0:
            logger.info(f"Repository limit set to {repo_limit}")
            
        # Create GitHub client with token manager if available
        if token_manager:
            github_client = GitHubClient(org=org, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
            analyzer = GitHubSecurityAnalyzer(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
        else:
            # Legacy single token mode
            analyzer = GitHubSecurityAnalyzer(token, org, storage_client, repo_limit)
            
        report = analyzer.generate_report()
        
        return jsonify({
            "status": "success",
            "organization": org,
            "repo_limit_applied": repo_limit if repo_limit > 0 else None,
            "report_file": report.get("report_file"),
            "summary": {
                "total_repositories": report.get("total_repositories"),
                "archived_repositories": report.get("archived_repositories", 0),
                "advanced_security_enabled": report.get("security_features", {}).get("advanced_security_enabled", 0),
                "secret_scanning_enabled": report.get("security_features", {}).get("secret_scanning_enabled", 0),
                "total_security_alerts": sum([
                    report.get("alert_counts", {}).get("total_secret_scanning_alerts", 0),
                    report.get("alert_counts", {}).get("total_code_scanning_alerts", 0),
                    report.get("alert_counts", {}).get("total_dependabot_alerts", 0)
                ])
            }
        }), 200
    except Exception as e:
        logger.exception(f"Error scanning security: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/organizations', methods=['GET'])
def list_organizations():
    """Endpoint to list accessible organizations"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        token = DEFAULT_CONFIG['GITHUB_TOKEN']
    
    if not token and not token_manager:
        return jsonify({"error": "Missing authorization"}), 401
    
    try:
        # Use token manager if available
        if token_manager:
            # Create a GitHub client without specifying an org
            client = GitHubClient(org="", token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
        else:
            # Legacy single token mode
            client = GitHubClient(token, "")
        
        # Get organizations using the /user/orgs endpoint
        url = f"{client.base_url}/user/orgs"
        response = client.make_request(url)
        
        if response.status_code != 200:
            return jsonify({"error": f"Failed to get organizations: {response.text}"}), response.status_code
            
        organizations = response.json()
        
        return jsonify({
            "status": "success",
            "count": len(organizations),
            "organizations": [
                {
                    "login": org["login"],
                    "id": org["id"],
                    "url": org["url"],
                    "repos_url": org["repos_url"],
                    "description": org.get("description")
                } for org in organizations
            ]
        }), 200
    except Exception as e:
        logger.exception(f"Error listing organizations: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/scan/all', methods=['POST'])
def scan_all_orgs():
    """Endpoint to scan all accessible organizations"""
    data = request.get_json() or {}
    
    # Get parameters from request or use defaults
    token = data.get('token') or DEFAULT_CONFIG['GITHUB_TOKEN']
    bucket_name = data.get('bucket') or DEFAULT_CONFIG['GCS_BUCKET']
    scan_type = data.get('scan_type', 'security')  # 'security' or 'actions' or 'all'
    repo_limit = data.get('repo_limit', DEFAULT_CONFIG['REPO_LIMIT'])
    
    if not token and not token_manager:
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize storage client
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Create a GitHub client without specifying an org
        if token_manager:
            client = GitHubClient(org="", token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
        else:
            client = GitHubClient(token, "")
        
        # Get organizations using the /user/orgs endpoint
        url = f"{client.base_url}/user/orgs"
        response = client.make_request(url)
        
        if response.status_code != 200:
            return jsonify({"error": f"Failed to get organizations: {response.text}"}), response.status_code
            
        organizations = response.json()
        
        if not organizations:
            return jsonify({"error": "No organizations found"}), 404
        
        # Results container
        results = {
            "status": "success",
            "scan_started_at": datetime.now().isoformat(),
            "scan_type": scan_type,
            "repo_limit_applied": repo_limit if repo_limit > 0 else None,
            "organizations_count": len(organizations),
            "organizations": []
        }
        
        # Scan each organization
        for org in organizations:
            org_name = org["login"]
            logger.info(f"Scanning organization: {org_name}")
            
            org_result = {
                "name": org_name,
                "scans": {}
            }
            
            # Run security scan if requested
            if scan_type in ['security', 'all']:
                try:
                    if token_manager:
                        # Create GitHub client with token manager
                        github_client = GitHubClient(org=org_name, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
                        security_analyzer = GitHubSecurityAnalyzer(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
                    else:
                        # Legacy single token mode
                        security_analyzer = GitHubSecurityAnalyzer(token, org_name, storage_client, repo_limit)
                        
                    security_report = security_analyzer.generate_report()
                    org_result["scans"]["security"] = {
                        "status": "success",
                        "report_file": security_report.get("report_file"),
                        "summary": {
                            "total_repositories": security_report.get("total_repositories", 0),
                            "advanced_security_enabled": security_report.get("security_features", {}).get("advanced_security_enabled", 0),
                            "secret_scanning_enabled": security_report.get("security_features", {}).get("secret_scanning_enabled", 0),
                            "total_security_alerts": sum([
                                security_report.get("alert_counts", {}).get("total_secret_scanning_alerts", 0),
                                security_report.get("alert_counts", {}).get("total_code_scanning_alerts", 0),
                                security_report.get("alert_counts", {}).get("total_dependabot_alerts", 0)
                            ])
                        }
                    }
                except Exception as e:
                    logger.exception(f"Error scanning security for {org_name}: {str(e)}")
                    org_result["scans"]["security"] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Run actions scan if requested
            if scan_type in ['actions', 'all']:
                try:
                    if token_manager:
                        # Create GitHub client with token manager
                        github_client = GitHubClient(org=org_name, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
                        actions_analyzer = GitHubActionsAnalyzer(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
                    else:
                        # Legacy single token mode
                        actions_analyzer = GitHubActionsAnalyzer(token, org_name, storage_client, repo_limit)
                        
                    actions_report = actions_analyzer.generate_report()
                    org_result["scans"]["actions"] = {
                        "status": "success",
                        "report_file": actions_report.get("report_file"),
                        "summary": {
                            "total_repositories": actions_report.get("total_repositories", 0),
                            "repositories_with_workflows": actions_report.get("repositories_with_workflows", 0),
                            "total_actions_used": actions_report.get("total_actions_used", 0),
                            "unique_actions_used": actions_report.get("unique_actions_used", 0)
                        }
                    }
                except Exception as e:
                    logger.exception(f"Error scanning actions for {org_name}: {str(e)}")
                    org_result["scans"]["actions"] = {
                        "status": "error",
                        "error": str(e)
                    }