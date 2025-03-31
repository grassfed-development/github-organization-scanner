import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import scanner components
from utils.github_client import GitHubClient  # Using original name
from scanners.actions_scanner import GitHubActionsAnalyzer  # Using correct class name
from scanners.security_scanner import GitHubSecurityAnalyzer  # Using original name
from storage.gcs_client import GCSClient
from utils.logger import setup_logger

app = Flask(__name__)

# Default configuration
DEFAULT_CONFIG = {
    'LOG_LEVEL': os.environ.get('LOG_LEVEL', 'INFO'),
    'GITHUB_TOKEN': os.environ.get('GITHUB_TOKEN'),
    'GITHUB_ORG': os.environ.get('GITHUB_ORG'),
    'GCS_BUCKET': os.environ.get('BUCKET_NAME'),
    'BASE_URL': os.environ.get('BASE_URL', 'https://api.github.com'),
    'DEBUG': os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't'),
    'PORT': int(os.environ.get('PORT', 8080)),
    'REPORTS_DIR': os.environ.get('REPORTS_DIR', 'reports')
}

# Check if token is available
if not DEFAULT_CONFIG['GITHUB_TOKEN']:
    print("ERROR - Missing required environment variable GITHUB_TOKEN")
    print("Please set GITHUB_TOKEN in your .env file or environment")
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
    
    if not all([token, org]):
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize storage client
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Run scanner
        logger.info(f"Starting Actions scan for {org}...")
        analyzer = GitHubActionsAnalyzer(token, org, storage_client)
        report = analyzer.generate_report()
        
        return jsonify({
            "status": "success",
            "organization": org,
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
    
    if not all([token, org]):
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize storage client
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Run scanner
        logger.info(f"Starting Security scan for {org}...")
        analyzer = GitHubSecurityAnalyzer(token, org, storage_client)
        report = analyzer.generate_report()
        
        return jsonify({
            "status": "success",
            "organization": org,
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
    
    if not token:
        return jsonify({"error": "Missing authorization"}), 401
    
    try:
        # Create a GitHub client without specifying an org
        # We'll use a special client just for this endpoint since we're not targeting a specific org
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
    
    if not token:
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize storage client
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Create a GitHub client without specifying an org
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
                    security_analyzer = GitHubSecurityAnalyzer(token, org_name, storage_client)
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
                    actions_analyzer = GitHubActionsAnalyzer(token, org_name, storage_client)
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
        "version": "2.0.0",
        "usage": {
            "list_organizations": "GET /organizations",
            "scan_all_organizations": "POST /scan/all",
            "scan_actions": "POST /scan/actions",
            "scan_security": "POST /scan/security"
        }
    }), 200

def run_local():
    """Run scanners locally for testing"""
    if not DEFAULT_CONFIG['GITHUB_TOKEN']:
        logger.error("Missing required environment variable GITHUB_TOKEN")
        return
    
    storage_client = GCSClient(DEFAULT_CONFIG['GCS_BUCKET']) if DEFAULT_CONFIG['GCS_BUCKET'] else None
    
    # Create a GitHub client without specifying an org
    client = GitHubClient(token=DEFAULT_CONFIG['GITHUB_TOKEN'], org="")
    
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
        actions_analyzer = GitHubActionsAnalyzer(DEFAULT_CONFIG['GITHUB_TOKEN'], org_name, storage_client)
        actions_analyzer.generate_report()
        
        # Run Security scanner
        logger.info(f"Running GitHub Security scan for {org_name}...")
        security_analyzer = GitHubSecurityAnalyzer(DEFAULT_CONFIG['GITHUB_TOKEN'], org_name, storage_client)
        security_analyzer.generate_report()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'local':
        # Run scanners locally
        run_local()
    else:
        # Run Flask app for development
        app.run(host='0.0.0.0', port=DEFAULT_CONFIG['PORT'], debug=DEFAULT_CONFIG['DEBUG'])