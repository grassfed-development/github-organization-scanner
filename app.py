import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify

from scanners.actions_scanner import GitHubActionsAnalyzer
from scanners.security_scanner import GitHubSecurityAnalyzer
from storage.gcs_client import GCSClient
from utils.logger import setup_logger
from utils.organization_lister import GitHubOrgLister
from config import Config

app = Flask(__name__)
config = Config()
setup_logger(config.LOG_LEVEL)
logger = logging.getLogger(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200

@app.route('/scan/actions', methods=['POST'])
def scan_actions():
    """Endpoint to scan GitHub Actions"""
    data = request.get_json() or {}
    
    # Get parameters from request or use defaults from config
    token = data.get('token') or config.GITHUB_TOKEN
    org = data.get('org') or config.GITHUB_ORG
    bucket_name = data.get('bucket') or config.GCS_BUCKET
    
    if not all([token, org]):
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize clients
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Run scanner
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
    
    # Get parameters from request or use defaults from config
    token = data.get('token') or config.GITHUB_TOKEN
    org = data.get('org') or config.GITHUB_ORG
    bucket_name = data.get('bucket') or config.GCS_BUCKET
    
    if not all([token, org]):
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize clients
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Run scanner
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
        token = config.GITHUB_TOKEN
    
    if not token:
        return jsonify({"error": "Missing authorization"}), 401
    
    try:
        org_lister = GitHubOrgLister(token)
        organizations = org_lister.list_user_organizations()
        
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
    
    # Get parameters from request or use defaults from config
    token = data.get('token') or config.GITHUB_TOKEN
    bucket_name = data.get('bucket') or config.GCS_BUCKET
    scan_type = data.get('scan_type', 'security')  # 'security' or 'actions' or 'all'
    
    if not token:
        return jsonify({"error": "Missing required parameters"}), 400
    
    try:
        # Initialize clients
        storage_client = GCSClient(bucket_name) if bucket_name else None
        
        # Get organizations
        org_lister = GitHubOrgLister(token)
        organizations = org_lister.list_user_organizations()
        
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
        "usage": {
            "list_organizations": "GET /organizations",
            "scan_all_organizations": "POST /scan/all",
            "scan_actions": "POST /scan/actions",
            "scan_security": "POST /scan/security"
        }
    }), 200

def run_local():
    """Run scanners locally for testing"""
    if not config.GITHUB_TOKEN:
        logger.error("Missing required environment variable GITHUB_TOKEN")
        return
    
    storage_client = GCSClient(config.GCS_BUCKET) if config.GCS_BUCKET else None
    
    # Get a list of organizations
    logger.info("Fetching accessible organizations...")
    org_lister = GitHubOrgLister(config.GITHUB_TOKEN)
    organizations = org_lister.list_user_organizations()
    
    if not organizations:
        logger.error("No organizations found for the user")
        return
    
    logger.info(f"Found {len(organizations)} organizations")
    
    # Set a specific org if provided, otherwise process all orgs
    target_orgs = []
    if config.GITHUB_ORG:
        target_orgs = [config.GITHUB_ORG]
        logger.info(f"Using specified organization: {config.GITHUB_ORG}")
    else:
        target_orgs = [org['login'] for org in organizations]
        logger.info(f"Processing all {len(target_orgs)} organizations")
    
    for org_name in target_orgs:
        logger.info(f"Processing organization: {org_name}")
        
        # Run Actions scanner
        logger.info(f"Running GitHub Actions scan for {org_name}...")
        actions_analyzer = GitHubActionsAnalyzer(config.GITHUB_TOKEN, org_name, storage_client)
        actions_analyzer.generate_report()
        
        # Run Security scanner
        logger.info(f"Running GitHub Security scan for {org_name}...")
        security_analyzer = GitHubSecurityAnalyzer(config.GITHUB_TOKEN, org_name, storage_client)
        security_analyzer.generate_report()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'local':
        # Run scanners locally
        run_local()
    else:
        # Run Flask app for development
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=config.DEBUG)