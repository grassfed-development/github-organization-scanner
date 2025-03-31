import os
import json
import logging
import argparse
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import scanner components
from utils.github_client import GitHubClient
from utils.github_token_manager import GitHubTokenManager
from scanners.actions_scanner import GitHubActionsAnalyzer
from scanners.security_scanner import GitHubSecurityAnalyzer
from storage.gcs_client import GCSClient
from utils.logger import setup_logger
from config import GITHUB_TOKENS_BY_SCOPE, GITHUB_TOKEN

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
    'REPO_LIMIT': int(os.environ.get('REPO_LIMIT', 0))  # 0 means no limit
}

# Check if token is available
if not DEFAULT_CONFIG['GITHUB_TOKEN'] and not DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE']:
    print("ERROR - Missing required GitHub token configuration")
    print("Please set GITHUB_TOKEN in your .env file or environment")
    print("  OR")
    print("Set token scope environment variables (GITHUB_TOKENS_REPO, etc.)")
    print("Current environment variables:", list(os.environ.keys()))
    print("Current working directory:", os.getcwd())
    print("Looking for .env file at:", os.path.join(os.getcwd(), '.env'))
    
    # Check if .env file exists
    env_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_path):
        print(".env file exists. Showing first few lines (without token):")
        with open(env_path, 'r') as f:
            for line in f:
                if not line.strip().startswith('GITHUB_TOKEN'):
                    print(line.strip())
                else:
                    print("GITHUB_TOKEN=***************")
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

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200

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
            
            # Add organization result to overall results
            results["organizations"].append(org_result)
        
        # Add completion timestamp
        results["scan_completed_at"] = datetime.now().isoformat()
        
        return jsonify(results), 200
    
    except Exception as e:
        logger.exception(f"Error in scan_all_orgs: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def index():
    """Default route with usage information"""
    return jsonify({
        "service": "GitHub Security Scanner",
        "version": "2.1.0",  # Bumped version for token manager
        "usage": {
            "list_organizations": "GET /organizations",
            "scan_all_organizations": "POST /scan/all",
            "scan_actions": "POST /scan/actions",
            "scan_security": "POST /scan/security"
        },
        "token_manager": "enabled" if token_manager else "disabled"
    }), 200

@app.route('/tokens/status', methods=['GET'])
def token_status():
    """Get status of all tokens and their rate limits"""
    if not token_manager:
        return jsonify({
            "token_manager": "disabled",
            "single_token": {
                "available": bool(DEFAULT_CONFIG['GITHUB_TOKEN']),
                "rate_limit": "Use the /rate_limit endpoint for details"
            }
        }), 200
    
    try:
        # Get rate limits for all tokens (obscure actual tokens)
        token_limits = token_manager.get_all_rate_limits()
        
        # Add count by scope
        scope_counts = {}
        for scope, tokens in DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE'].items():
            scope_counts[scope] = len(tokens)
        
        return jsonify({
            "token_manager": "enabled",
            "tokens_by_scope": scope_counts,
            "total_tokens": len(token_manager.all_tokens),
            "token_rate_limits": token_limits
        }), 200
    except Exception as e:
        logger.exception(f"Error getting token status: {str(e)}")
        return jsonify({"error": str(e)}), 500

def run_local():
    """Run scanners locally for testing"""
    if not DEFAULT_CONFIG['GITHUB_TOKEN'] and not token_manager:
        logger.error("Missing required GitHub token configuration")
        return
    
    storage_client = GCSClient(DEFAULT_CONFIG['GCS_BUCKET']) if DEFAULT_CONFIG['GCS_BUCKET'] else None
    repo_limit = DEFAULT_CONFIG['REPO_LIMIT']
    
    if repo_limit > 0:
        logger.info(f"Repository limit set to {repo_limit}")
    
    # Create a GitHub client without specifying an org
    if token_manager:
        client = GitHubClient(org="", token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
        logger.info("Using token manager for API requests")
    else:
        client = GitHubClient(token=DEFAULT_CONFIG['GITHUB_TOKEN'], org="")
        logger.info("Using single token mode for API requests")
    
    # Get a list of organizations
    logger.info("Fetching accessible organizations...")
    url = f"{client.base_url}/user/orgs"
    response = client.make_request(url)
    
    if response.status_code != 200:
        logger.error(f"Failed to get organizations: {response.text}")
        return
        
    organizations = response.json()
    
    if not organizations:
        logger.error("No organizations found for the user")
        return
    
    logger.info(f"Found {len(organizations)} organizations")
    
    # Set a specific org if provided, otherwise process all orgs
    target_orgs = []
    if DEFAULT_CONFIG['GITHUB_ORG']:
        target_orgs = [DEFAULT_CONFIG['GITHUB_ORG']]
        logger.info(f"Using specified organization: {DEFAULT_CONFIG['GITHUB_ORG']}")
    else:
        target_orgs = [org['login'] for org in organizations]
        logger.info(f"Processing all {len(target_orgs)} organizations")
    
    for org_name in target_orgs:
        logger.info(f"Processing organization: {org_name}")
        
        # Run Actions scanner
        logger.info(f"Running GitHub Actions scan for {org_name}...")
        if token_manager:
            # Create GitHub client with token manager
            github_client = GitHubClient(org=org_name, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
            actions_analyzer = GitHubActionsAnalyzer(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
        else:
            # Legacy single token mode
            actions_analyzer = GitHubActionsAnalyzer(DEFAULT_CONFIG['GITHUB_TOKEN'], org_name, storage_client, repo_limit)
            
        actions_analyzer.generate_report()
        
        # Run Security scanner
        logger.info(f"Running GitHub Security scan for {org_name}...")
        if token_manager:
            # Create GitHub client with token manager
            github_client = GitHubClient(org=org_name, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
            security_analyzer = GitHubSecurityAnalyzer(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
        else:
            # Legacy single token mode
            security_analyzer = GitHubSecurityAnalyzer(DEFAULT_CONFIG['GITHUB_TOKEN'], org_name, storage_client, repo_limit)
            
        security_analyzer.generate_report()

if __name__ == '__main__':
    import sys
    
    parser = argparse.ArgumentParser(description="GitHub Organization Scanner")
    parser.add_argument('mode', nargs='?', default='server', choices=['local', 'server'], 
                      help="Run mode: 'local' for local scanning, 'server' for web server")
    parser.add_argument('--limit', type=int, default=DEFAULT_CONFIG['REPO_LIMIT'],
                      help="Limit the number of repositories to scan")
    parser.add_argument('--token-status', action='store_true',
                      help="Show status of available tokens and exit")
    
    args = parser.parse_args()
    
    # Override repo limit if specified on command line
    if args.limit > 0:
        DEFAULT_CONFIG['REPO_LIMIT'] = args.limit
    
    # Just show token status if requested
    if args.token_status:
        if token_manager:
            print(f"Token manager enabled with {len(token_manager.all_tokens)} tokens")
            token_limits = token_manager.get_all_rate_limits()
            for token_id, limit_info in token_limits.items():
                print(f"Token {token_id}: {limit_info['remaining']}/{limit_info['limit']} remaining, resets at {datetime.fromtimestamp(limit_info['reset'])}")
            
            # Show token counts by scope
            print("\nTokens by scope:")
            for scope, tokens in DEFAULT_CONFIG['GITHUB_TOKENS_BY_SCOPE'].items():
                if tokens:
                    print(f"  {scope}: {len(tokens)} tokens")
        else:
            print("Token manager disabled. Using single token mode.")
            if DEFAULT_CONFIG['GITHUB_TOKEN']:
                print("Single token available.")
            else:
                print("No token available! Please set GITHUB_TOKEN in your environment.")
        sys.exit(0)
        
    if args.mode == 'local' or (len(sys.argv) > 1 and sys.argv[1] == 'local'):
        # Run scanners locally
        run_local()
    else:
        # Run Flask app
        app.run(host='0.0.0.0', port=DEFAULT_CONFIG['PORT'], debug=DEFAULT_CONFIG['DEBUG'])