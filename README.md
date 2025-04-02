# GitHub Organization Scanner

A comprehensive Python-based scanning service for GitHub Organizations to monitor security settings, vulnerabilities, and GitHub Actions usage with Google Cloud Platform integration, Google Cloud Secret Manager support, and HashiCorp Vault support.

## Features

- Efficiently scans multiple GitHub organizations
- Analyzes security features across repositories:
  - Advanced Security
  - Secret Scanning
  - Secret Scanning Push Protection
  - Vulnerability Alerts
  - Automated Security Fixes
- Detects and reports on security alerts:
  - Secret Scanning Alerts
  - Code Scanning Alerts
  - Dependabot Alerts
- Analyzes GitHub Actions usage across repositories
- Supports local execution and Google Cloud Run deployment
- Stores reports locally and in Google Cloud Storage
- API-based architecture with Flask web service
- Rate limit optimization through intelligent waiting
- Repository limit option for faster testing and debugging
- **HashiCorp Vault integration for secure token management**
- **Google Cloud Secret Manager integration for secure token management**

## Architecture

- **Python-based**: Built with Python 3.11+
- **Google Cloud Storage**: Optional cloud storage for reports
- **Google Cloud Secret Manager**: Secure storage and retrieval of GitHub tokens
- **Flask Web Service**: RESTful API for remote scanning
- **Organization-Level APIs**: Prioritizes GitHub's organization-level endpoints for efficient scanning
- **HashiCorp Vault**: Secure storage and retrieval of GitHub tokens

## Installation

### Prerequisites

- Python 3.11+
- GitHub Personal Access Token with appropriate scopes
- Google Cloud SDK (for GCP deployment)
- Google Cloud Storage bucket (optional)
- Google Cloud Secret Manager (optional, recommended for secure token management)
- HashiCorp Vault (optional, recommended for secure token management)

### Local Setup

1. Clone the repository:
```bash
git clone https://github.com/your-username/github-organization-scanner.git
cd github-organization-scanner
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your configuration:
```bash
cp .env.example .env
```

5. Edit the `.env` file with your settings, including your GitHub tokens OR Vault/GCP Secret Manager configuration:
```
# GitHub Token (For local development or fallback)
GITHUB_TOKEN=ghp_your_token_here

# OR Vault Configuration (Primary)
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=hvs.example_token
# VAULT_GITHUB_MOUNT=github  # Optional, defaults to 'github'

# OR GCP Secret Manager Configuration (Secondary)
GCP_PROJECT_ID=your-gcp-project-id
```

## Token Access Methods

The application attempts to retrieve GitHub tokens in the following order:

### 1. HashiCorp Vault (Primary)

The application will first attempt to retrieve tokens from Vault:

```bash
# Required: Vault server URL
VAULT_ADDR=https://vault.example.com:8200

# Authentication - Choose one method:
VAULT_TOKEN=hvs.example_token  # Direct token
# OR
VAULT_ROLE_ID=12345678-abcd-1234-abcd-123456789abc  # AppRole
VAULT_SECRET_ID=98765432-abcd-1234-abcd-987654321fed

# Optional: Custom mount point for GitHub tokens
VAULT_GITHUB_MOUNT=github  # Default
```

See the [Vault Integration](#vault-integration) section for detailed setup instructions.

### 2. Google Cloud Secret Manager (Secondary)

If Vault is unavailable or not configured, the application will try to retrieve tokens from Google Cloud Secret Manager:

```bash
# Required: GCP Project ID
GCP_PROJECT_ID=your-gcp-project-id
```

See the [GCP Secret Manager Integration](#gcp-secret-manager-integration) section for detailed setup instructions.

### 3. Environment Variables (Fallback)

If both Vault and GCP Secret Manager are unavailable or not configured, the application will use tokens from environment variables:

```bash
# Single token option
GITHUB_TOKEN=ghp_your_token_here

# OR multiple tokens by scope
GITHUB_TOKENS_REPO=ghp_token1_with_repo_scope,ghp_token2_with_repo_scope
GITHUB_TOKENS_SECURITY_EVENTS=ghp_token_with_security_events_scope
GITHUB_TOKENS_READ_ORG=ghp_token_with_read_org_scope
GITHUB_TOKENS_WORKFLOW=ghp_token_with_workflow_scope
```

## Token Permissions

For optimal functionality, your GitHub tokens should have these scopes:
- `repo` - For repository access
- `read:org` - For listing organizations
- `security_events` - For security scanning
- `workflow` - For Actions scanning

## Usage

### Running Locally

Run a scan directly without using the web server:

```bash
# Scan all repositories in all accessible organizations
python app.py local

# Scan with a repository limit (useful for testing)
python app.py local --limit 50

# Check token status
python app.py --token-status

# Alternatively, set REPO_LIMIT in .env file
```

### Web Server Mode

Run the scanner as a web service:

```bash
# Start the web server 
python app.py
```

Then use the API endpoints:

1. List organizations:
   ```bash
   curl http://localhost:8080/organizations
   ```

2. Run a security scan:
   ```bash
   curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"org": "your-org-name", "repo_limit": 50}' \
     http://localhost:8080/scan/security
   ```

3. Run an Actions scan:
   ```bash
   curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"org": "your-org-name"}' \
     http://localhost:8080/scan/actions
   ```

4. Scan all organizations:
   ```bash
   curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"scan_type": "all"}' \
     http://localhost:8080/scan/all
   ```

5. Check Vault status:
   ```bash
   curl http://localhost:8080/vault/status
   ```

6. Check GCP Secret Manager status:
   ```bash
   curl http://localhost:8080/gcp-secret/status
   ```

7. Check token status:
   ```bash
   curl http://localhost:8080/tokens/status
   ```

## How to Add New Components

The GitHub Organization Scanner is designed to be extensible. Here's how to add new scanners or utilities to the system.

### Creating a New Scanner

1. **Create a new scanner file** in the `scanners` directory:
   ```
   scanners/your_new_scanner.py
   ```

2. **Extend the BaseScanner class**:
   ```python
   from scanners.base_scanner import BaseScanner
   
   class YourNewScanner(BaseScanner):
       def __init__(self, token=None, org=None, storage_client=None, repo_limit=0, client=None):
           # Use provided GitHub client or create one
           if client:
               github_client = client
               self.org = client.org
           else:
               # Legacy mode - create client with token
               github_client = GitHubClient(token, org)
               self.org = org
               
           super().__init__(github_client, storage_client)
           self.repo_limit = repo_limit
           
       def scan(self, repo_limit=0):
           """Implement your scanning logic here"""
           # Get repositories
           repos = self.github_client.get_all_repositories()
           
           # Apply repository limit if specified
           limit = repo_limit or self.repo_limit
           if limit > 0 and len(repos) > limit:
               repos = repos[:limit]
           
           # Your scanning logic here
           results = {}
           
           # Return results dictionary
           return results
       
       def generate_report(self):
           """Generate a report from scan results"""
           data = self.scan(self.repo_limit)
           
           # Log summary information
           logger.info("=" * 50)
           logger.info(f"Your New Scanner Report for {self.org}")
           logger.info("=" * 50)
           # Add your summary logging here
           
           # Save report
           data = self.save_report(data)
           return data
   ```

3. **Add an endpoint to app.py**:
   ```python
   @app.route('/scan/your-new-scan', methods=['POST'])
   def scan_your_new():
       """Endpoint for your new scanner"""
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
           logger.info(f"Starting Your New scan for {org}...")
           
           # Create GitHub client with token manager if available
           if token_manager:
               github_client = GitHubClient(org=org, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
               analyzer = YourNewScanner(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
           else:
               # Legacy single token mode
               analyzer = YourNewScanner(token, org, storage_client, repo_limit)
               
           report = analyzer.generate_report()
           
           # Customize response structure based on your scanner's output
           return jsonify({
               "status": "success",
               "organization": org,
               "repo_limit_applied": repo_limit if repo_limit > 0 else None,
               "report_file": report.get("report_file"),
               "summary": {
                   # Include relevant summary fields from your scanner
               }
           }), 200
       except Exception as e:
           logger.exception(f"Error running your new scan: {str(e)}")
           return jsonify({"error": str(e)}), 500
   ```

4. **Update the index route** to include your new endpoint:
   ```python
   @app.route('/', methods=['GET'])
   def index():
       """Default route with usage information"""
       return jsonify({
           "service": "GitHub Security Scanner",
           "version": "2.3.0",
           "usage": {
               # ... existing endpoints ...
               "scan_your_new": "POST /scan/your-new-scan",
           },
           # ... other details ...
       }), 200
   ```

5. **Add your scanner to the local run function** if needed:
   ```python
   def run_local():
       # ... existing code ...
       
       for org_name in target_orgs:
           # ... existing scanners ...
           
           # Run Your New scanner
           logger.info(f"Running Your New scan for {org_name}...")
           if token_manager:
               github_client = GitHubClient(org=org_name, token_manager=token_manager, base_url=DEFAULT_CONFIG['BASE_URL'])
               your_analyzer = YourNewScanner(client=github_client, storage_client=storage_client, repo_limit=repo_limit)
           else:
               your_analyzer = YourNewScanner(DEFAULT_CONFIG['GITHUB_TOKEN'], org_name, storage_client, repo_limit)
               
           your_analyzer.generate_report()
   ```

### Creating a New Utility

1. **Create a new utility file** in the `utils` directory:
   ```
   utils/your_utility.py
   ```

2. **Implement your utility class**:
   ```python
   import logging
   
   logger = logging.getLogger(__name__)
   
   class YourUtility:
       """Utility for [purpose]"""
       
       def __init__(self, config1=None, config2=None):
           """Initialize your utility with necessary configuration"""
           self.config1 = config1
           self.config2 = config2
           logger.info("Initialized YourUtility")
           
       def your_method(self, param1, param2):
           """
           Description of what your method does
           
           Args:
               param1: Description of param1
               param2: Description of param2
               
           Returns:
               Description of return value
           """
           logger.info(f"Running your_method with {param1}, {param2}")
           
           # Your implementation here
           result = self._internal_helper(param1, param2)
           
           return result
           
       def _internal_helper(self, param1, param2):
           """Internal helper method (private)"""
           # Implementation details
           return some_result
   ```

3. **Import and use your utility** in other components as needed:
   ```python
   from utils.your_utility import YourUtility
   
   # In your scanner or other code
   utility = YourUtility(config1="value1", config2="value2")
   result = utility.your_method("param1", "param2")
   ```

### Best Practices for New Components

1. **Follow the existing pattern** for rate limit handling, pagination, and error handling.
2. **Use the logger** for consistent logging throughout the application.
3. **Handle exceptions** and provide meaningful error messages.
4. **Add appropriate documentation** in docstrings and comments.
5. **Consider token scopes** required for your new functionality.
6. **Use organization-level APIs** when possible for better efficiency.
7. **Support both token manager** and single token modes for backward compatibility.
8. **Add tests** for your new components (if applicable).

## Vault Integration

HashiCorp Vault is used for secure storage and retrieval of GitHub tokens.

### Vault Secret Structure

GitHub tokens should be stored in Vault using the following structure:

#### Single Token (Legacy)

```
# Path: <mount_point>/token
{
  "value": "ghp_your_token_here"
}
```

#### Scoped Tokens (Recommended)

```
# Path: <mount_point>/tokens/repo
{
  "token1": "ghp_token1_with_repo_scope",
  "token2": "ghp_token2_with_repo_scope",
  "token3": "ghp_token3_with_repo_scope"
}

# Path: <mount_point>/tokens/security_events
{
  "token1": "ghp_token_with_security_events_scope"
}

# Path: <mount_point>/tokens/read_org
{
  "token1": "ghp_token_with_read_org_scope"
}

# Path: <mount_point>/tokens/workflow
{
  "token1": "ghp_token_with_workflow_scope"
}
```

### Vault Setup Commands

Here are example commands to set up Vault for this application:

```bash
# Enable KV secrets engine v2
vault secrets enable -version=2 -path=github kv

# Store a single token
vault kv put github/token value=ghp_your_token_here

# Store scoped tokens
vault kv put github/tokens/repo \
  token1=ghp_token1_with_repo_scope \
  token2=ghp_token2_with_repo_scope

vault kv put github/tokens/security_events \
  token1=ghp_token_with_security_events_scope

vault kv put github/tokens/read_org \
  token1=ghp_token_with_read_org_scope

vault kv put github/tokens/workflow \
  token1=ghp_token_with_workflow_scope
```

## GCP Secret Manager Integration

Google Cloud Secret Manager is used as a secondary option for secure storage and retrieval of GitHub tokens.

### Secret Structure

GitHub tokens should be stored in Secret Manager using the following structure:

#### Single Token (Legacy)

```
Secret Name: github-token
Value: ghp_your_token_here
```

#### Scoped Tokens (Recommended)

Store tokens as JSON arrays:

```
Secret Name: github-tokens-repo
Value: ["ghp_token1_with_repo_scope", "ghp_token2_with_repo_scope", "ghp_token3_with_repo_scope"]

Secret Name: github-tokens-security_events
Value: ["ghp_token_with_security_events_scope"]

Secret Name: github-tokens-read_org
Value: ["ghp_token_with_read_org_scope"]

Secret Name: github-tokens-workflow
Value: ["ghp_token_with_workflow_scope"]
```

### GCP Secret Manager Setup Commands

Here are example commands to set up Secret Manager for this application:

```bash
# Create single token secret
echo -n "ghp_your_token_here" | \
  gcloud secrets create github-token \
  --data-file=- \
  --replication-policy="automatic"

# Create scoped token secrets (as JSON arrays)
echo -n '["ghp_token1_with_repo_scope", "ghp_token2_with_repo_scope"]' | \
  gcloud secrets create github-tokens-repo \
  --data-file=- \
  --replication-policy="automatic"

echo -n '["ghp_token_with_security_events_scope"]' | \
  gcloud secrets create github-tokens-security_events \
  --data-file=- \
  --replication-policy="automatic"

echo -n '["ghp_token_with_read_org_scope"]' | \
  gcloud secrets create github-tokens-read_org \
  --data-file=- \
  --replication-policy="automatic"

echo -n '["ghp_token_with_workflow_scope"]' | \
  gcloud secrets create github-tokens-workflow \
  --data-file=- \
  --replication-policy="automatic"
```

### Accessing Secrets in Google Cloud Run

When deploying to Cloud Run, you'll need to give the service access to Secret Manager:

```bash
# Grant Secret Manager Secret Accessor role to the service account
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor
```

## Google Cloud Platform Deployment

### Google Cloud Run

1. Build the container:
```bash
gcloud builds submit --tag gcr.io/your-project/github-security-scanner
```

2. Deploy to Cloud Run:
```bash
gcloud run deploy github-security-scanner \
  --image gcr.io/your-project/github-security-scanner \
  --platform managed \
  --region us-central1 \
  --set-env-vars "GCS_BUCKET=your-bucket-name,GCP_PROJECT_ID=your-project-id"
```

3. Set up Secret Manager for GitHub tokens (as shown in the GCP Secret Manager Integration section).

4. Or if using Vault, set up Secret Manager for Vault authentication:
```bash
# For token authentication
gcloud secrets create vault-token --replication-policy automatic
echo -n "YOUR_VAULT_TOKEN" | gcloud secrets versions add vault-token --data-file=-

# For AppRole authentication
gcloud secrets create vault-role-id --replication-policy automatic
echo -n "YOUR_VAULT_ROLE_ID" | gcloud secrets versions add vault-role-id --data-file=-

gcloud secrets create vault-secret-id --replication-policy automatic
echo -n "YOUR_VAULT_SECRET_ID" | gcloud secrets versions add vault-secret-id --data-file=-
```

5. Update the Cloud Run service to use the secrets:
```bash
# For Vault token authentication
gcloud run services update github-security-scanner \
  --set-secrets=VAULT_TOKEN=vault-token:latest

# For Vault AppRole authentication
gcloud run services update github-security-scanner \
  --set-secrets=VAULT_ROLE_ID=vault-role-id:latest,VAULT_SECRET_ID=vault-secret-id:latest
```

### Cloud Scheduler Integration

Automate regular scanning with Cloud Scheduler:

1. Create a service account:
```bash
gcloud iam service-accounts create github-scanner-invoker
```

2. Grant permission to invoke the Cloud Run service:
```bash
gcloud run services add-iam-policy-binding github-security-scanner \
  --member=serviceAccount:github-scanner-invoker@your-project.iam.gserviceaccount.com \
  --role=roles/run.invoker
```

3. Create a scheduler job:
```bash
gcloud scheduler jobs create http github-scanner-weekly \
  --schedule="0 0 * * 0" \
  --uri="https://github-security-scanner-url/scan/all" \
  --http-method=POST \
  --headers="Content-Type=application/json" \
  --body='{"scan_type":"all"}' \
  --oidc-service-account-email=github-scanner-invoker@your-project.iam.gserviceaccount.com
```

## Reports

Reports are generated in two formats:
1. Console output - Summary of findings
2. JSON files - Detailed scan results

JSON reports are saved:
- Locally: In the `reports/` directory
- Cloud: In the GCS bucket (if configured) under `github_scanner/{scan_type}/{filename}`

## Troubleshooting

### Token Access Issues

If you experience issues with token access:

1. Check Vault connectivity:
   ```bash
   curl http://localhost:8080/vault/status
   ```

2. Check GCP Secret Manager connectivity:
   ```bash
   curl http://localhost:8080/gcp-secret/status
   ```

3. Check token status:
   ```bash
   curl http://localhost:8080/tokens/status
   ```

4. Verify Vault is properly configured:
   - Ensure `VAULT_ADDR` points to a reachable Vault server
   - Check that the authentication credentials are correct
   - Verify the secrets exist at the expected paths

5. Verify GCP Secret Manager is properly configured:
   - Ensure `GCP_PROJECT_ID` is set correctly
   - Check that the service account has access to Secret Manager
   - Verify the secrets exist with the expected names

6. If using environment variables:
   - Ensure the token has the necessary scopes
   - For organization-level operations, ensure the "Grant organization access" checkbox was selected when creating the token

### Rate Limiting Issues

If you encounter rate limiting issues:

1. Check the logs for warnings about rate limits
2. The scanner will automatically wait for the rate limit to reset
3. For large organizations, consider using the `REPO_LIMIT` setting during testing
4. Add more tokens with appropriate scopes in Vault or GCP Secret Manager

### Permission Issues

If you encounter permission errors:

1. Ensure your tokens have the necessary scopes (repo, read:org, security_events, workflow)
2. Verify the token owner has appropriate access to the organization
3. For organization-level operations, ensure the "Grant organization access" checkbox was selected when creating the token

## License

[MIT License](LICENSE)