# GitHub Organization Scanner

A comprehensive scanning service for GitHub Organizations to monitor security settings, vulnerabilities, and GitHub Actions usage.

## Features

- Scans multiple GitHub organizations
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
- Supports local execution and Cloud Run deployment
- Stores reports locally and in Google Cloud Storage
- Advanced token management with permission-based scopes
- Rate limit optimization through token rotation

## Installation

### Prerequisites

- Python 3.11+
- GitHub Personal Access Tokens with appropriate scopes (see Token Management section)
- Google Cloud Storage bucket (for cloud storage support)

### Local Setup

1. Clone the repository:
```bash
git clone https://github.com/your-username/github-security-scanner.git
cd github-security-scanner
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
# Copy the example file
cp .env.example .env

# Edit with your settings
nano .env
```

## Token Management

The application uses a sophisticated token management system that allows you to use multiple GitHub tokens with different permission scopes. This approach follows the principle of least privilege while avoiding rate limiting issues when scanning large organizations.

### Permission Scopes

For optimal security, create tokens with only the required permissions for each operation:

| Operation | Required Scope | Description |
|-----------|---------------|-------------|
| Listing Organizations | `read:org` | Read-only access to list organizations |
| Listing Repositories | `repo:status` or `public_repo` | Minimal repository access |
| Scanning Actions | `workflow` | Access to GitHub Actions workflows |
| Security Scanning | `security_events` | Access to security vulnerabilities |
| Full Repository Access | `repo` | Full access to private repositories (use sparingly) |
| Organization Admin | `admin:org` | Admin access to organizations (use sparingly) |
| Runner Management | `manage_runners:org` | Access to organization runners |

### Configuring Tokens in `.env`

Configure your tokens by permission scope in the `.env` file:

```bash
# Single token (for backward compatibility)
GITHUB_TOKEN=ghp_your_legacy_token

# Repository access tokens
GITHUB_TOKENS_REPO=ghp_repo_token1,ghp_repo_token2
GITHUB_TOKENS_REPO_STATUS=ghp_status_token1,ghp_status_token2
GITHUB_TOKENS_PUBLIC_REPO=ghp_public_token1,ghp_public_token2

# Organization access tokens
GITHUB_TOKENS_READ_ORG=ghp_read_org_token1,ghp_read_org_token2,ghp_read_org_token3
GITHUB_TOKENS_ADMIN_ORG=ghp_admin_token1

# Security and workflow tokens
GITHUB_TOKENS_SECURITY_EVENTS=ghp_security_token1,ghp_security_token2
GITHUB_TOKENS_WORKFLOW=ghp_workflow_token1,ghp_workflow_token2

# Other configuration
GITHUB_ORG=optional_specific_org
BUCKET_NAME=your-bucket-name
LOG_LEVEL=INFO
```

### Best Practices for Token Management

1. **Create multiple tokens per scope**: For high-volume operations like repository listing, create 3-5 tokens with the same minimal scope to increase your effective rate limit.

2. **Use separate user accounts**: For optimal isolation, create tokens from different GitHub user accounts (all with access to your organization).

3. **Token rotation**: Create a process to rotate these tokens every 30-90 days.

4. **Add descriptive comments**: When creating tokens in GitHub, add comments like "GitHub Scanner - read:org only" to track their purpose.

5. **Prioritize least privilege**: Use more specific permission scopes whenever possible instead of broader ones.

### How Token Management Works

1. **Permission-Based Selection**: The system automatically selects tokens with the appropriate permissions for each operation.

2. **Rate Limit Awareness**: Tokens with the highest remaining rate limits are prioritized.

3. **Automatic Rotation**: As tokens approach their rate limits, the system rotates to others with the same permissions.

4. **Graceful Waiting**: If all tokens for a particular operation are rate-limited, the system will wait for the earliest reset time.

## Usage

### Running Locally

To run scans locally for all organizations you have access to:

```bash
python app.py local
```

To run the Flask web server locally:

```bash
python app.py
```

### API Endpoints

- `GET /health` - Health check endpoint
- `GET /organizations` - List accessible GitHub organizations
- `POST /scan/all` - Scan all accessible organizations
- `POST /scan/actions` - Scan a specific organization for GitHub Actions
- `POST /scan/security` - Scan a specific organization for security settings

#### Example Requests

List organizations:
```bash
curl -H "Authorization: Bearer YOUR_GITHUB_TOKEN" http://localhost:8080/organizations
```

Scan all organizations:
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_GITHUB_TOKEN", "scan_type": "all"}' \
  http://localhost:8080/scan/all
```

Scan a single organization:
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_GITHUB_TOKEN", "org": "your-org-name"}' \
  http://localhost:8080/scan/security
```

## Deployment

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
  --set-env-vars "GCS_BUCKET=your-bucket-name"
```

3. Set up Secret Manager for GitHub tokens:
```bash
# For the legacy single token
gcloud secrets create github-token --replication-policy automatic
echo -n "YOUR_GITHUB_TOKEN" | gcloud secrets versions add github-token --data-file=-

# For scoped tokens (example for read:org tokens)
gcloud secrets create github-tokens-read-org --replication-policy automatic
echo -n "ghp_token1,ghp_token2,ghp_token3" | gcloud secrets versions add github-tokens-read-org --data-file=-
```

4. Update the Cloud Run service to use the secrets:
```bash
gcloud run services update github-security-scanner \
  --set-secrets=GITHUB_TOKEN=github-token:latest,GITHUB_TOKENS_READ_ORG=github-tokens-read-org:latest
```

## Reports

Reports are generated in two formats:
1. Console output - Summary of findings
2. JSON files - Detailed scan results

JSON reports are saved:
- Locally: In the `reports/` directory
- Cloud: In the GCS bucket (if configured) under `github_scanner/{scan_type}/{filename}`

## Troubleshooting

### Rate Limiting Issues

If you encounter rate limiting issues:

1. Check the logs for warnings about rate limits
2. Verify your tokens have the correct scopes
3. Add more tokens to high-usage categories (particularly `repo` and `read:org`)
4. For very large organizations (1000+ repositories), you may need 5-10 tokens per category

### Permission Issues

If you encounter permission errors:

1. Ensure your tokens have the necessary scopes for the operations
2. Verify the token owner has appropriate access to the organization
3. For organization-level operations, ensure the "Grant organization access" checkbox was selected when creating the token

## License

[MIT License](LICENSE)