# GitHub Organization Scanner

A comprehensive Python-based scanning service for GitHub Organizations to monitor security settings, vulnerabilities, and GitHub Actions usage with Google Cloud Platform integration.

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

## Architecture

- **Python-based**: Built with Python 3.11+
- **Google Cloud Storage**: Optional cloud storage for reports
- **Flask Web Service**: RESTful API for remote scanning
- **Organization-Level APIs**: Prioritizes GitHub's organization-level endpoints for efficient scanning

## Installation

### Prerequisites

- Python 3.11+
- GitHub Personal Access Token with appropriate scopes
- Google Cloud SDK (for GCP deployment)
- Google Cloud Storage bucket (optional)

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

5. Edit the `.env` file with your settings, including your GitHub token:
```
GITHUB_TOKEN=ghp_your_token_here
```

## Token Permissions

For optimal functionality, your GitHub token should have these scopes:
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
  --set-env-vars "GCS_BUCKET=your-bucket-name"
```

3. Set up Secret Manager for GitHub tokens:
```bash
gcloud secrets create github-token --replication-policy automatic
echo -n "YOUR_GITHUB_TOKEN" | gcloud secrets versions add github-token --data-file=-
```

4. Update the Cloud Run service to use the secrets:
```bash
gcloud run services update github-security-scanner \
  --set-secrets=GITHUB_TOKEN=github-token:latest
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

### Rate Limiting Issues

If you encounter rate limiting issues:

1. Check the logs for warnings about rate limits
2. The scanner will automatically wait for the rate limit to reset
3. For large organizations, consider using the `REPO_LIMIT` setting during testing

### Permission Issues

If you encounter permission errors:

1. Ensure your token has the necessary scopes (repo, read:org, security_events, workflow)
2. Verify the token owner has appropriate access to the organization
3. For organization-level operations, ensure the "Grant organization access" checkbox was selected when creating the token

## License

[MIT License](LICENSE)