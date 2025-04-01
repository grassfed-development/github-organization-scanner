# GitHub Organization Scanner

A comprehensive Python-based scanning service for GitHub Organizations to monitor security settings, vulnerabilities, and GitHub Actions usage with Google Cloud Platform integration and HashiCorp Vault support.

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

## Architecture

- **Python-based**: Built with Python 3.11+
- **Google Cloud Storage**: Optional cloud storage for reports
- **Flask Web Service**: RESTful API for remote scanning
- **Organization-Level APIs**: Prioritizes GitHub's organization-level endpoints for efficient scanning
- **HashiCorp Vault**: Secure storage and retrieval of GitHub tokens

## Installation

### Prerequisites

- Python 3.11+
- GitHub Personal Access Token with appropriate scopes
- Google Cloud SDK (for GCP deployment)
- Google Cloud Storage bucket (optional)
- HashiCorp Vault (recommended for secure token management)

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

5. Edit the `.env` file with your settings, including your GitHub tokens OR Vault configuration:
```
# GitHub Token (For local development or fallback)
GITHUB_TOKEN=ghp_your_token_here

# OR Vault Configuration (Recommended)
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=hvs.example_token
# VAULT_GITHUB_MOUNT=github  # Optional, defaults to 'github'
```

## Token Access Methods

### 1. HashiCorp Vault (Recommended)

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

### 2. Environment Variables (Fallback)

If Vault is unavailable or not configured, the application will use tokens from environment variables:

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

6. Check token status:
   ```bash
   curl http://localhost:8080/tokens/status
   ```

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
  --set-env-vars "GCS_BUCKET=your-bucket-name,VAULT_ADDR=https://vault.example.com:8200"
```

3. Set up Secret Manager for Vault authentication:
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

4. Update the Cloud Run service to use the secrets:
```bash
# For token authentication
gcloud run services update github-security-scanner \
  --set-secrets=VAULT_TOKEN=vault-token:latest

# For AppRole authentication
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

## Future Development

This repository is specifically designed to work with Google Cloud Platform storage. A future repository will be developed for Azure Storage and Azure Functions integration.

## Troubleshooting

### Token Access Issues

If you experience issues with token access:

1. Check Vault connectivity:
   ```bash
   curl http://localhost:8080/vault/status
   ```

2. Check token status:
   ```bash
   curl http://localhost:8080/tokens/status
   ```

3. Verify Vault is properly configured:
   - Ensure `VAULT_ADDR` points to a reachable Vault server
   - Check that the authentication credentials are correct
   - Verify the secrets exist at the expected paths

4. If using environment variables:
   - Ensure the token has the necessary scopes
   - For organization-level operations, ensure the "Grant organization access" checkbox was selected when creating the token

### Rate Limiting Issues

If you encounter rate limiting issues:

1. Check the logs for warnings about rate limits
2. The scanner will automatically wait for the rate limit to reset
3. For large organizations, consider using the `REPO_LIMIT` setting during testing
4. Add more tokens with appropriate scopes in Vault

### Permission Issues

If you encounter permission errors:

1. Ensure your tokens have the necessary scopes (repo, read:org, security_events, workflow)
2. Verify the token owner has appropriate access to the organization
3. For organization-level operations, ensure the "Grant organization access" checkbox was selected when creating the token

## License

[MIT License](LICENSE)