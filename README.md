# GitHub Security Scanner

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

## Installation

### Prerequisites

- Python 3.11+
- GitHub Personal Access Token with appropriate scopes:
  - `repo` (full access to repositories)
  - `admin:org` (for organization settings)
  - `security_events` (for security alerts)
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

3. Set up Secret Manager for GitHub token:
```bash
gcloud secrets create github-token --replication-policy automatic
echo -n "YOUR_GITHUB_TOKEN" | gcloud secrets versions add github-token --data-file=-
```

4. Update the Cloud Run service to use the secret:
```bash
gcloud run services update github-security-scanner \
  --set-secrets=GITHUB_TOKEN=github-token:latest
```

## Reports

Reports are generated in two formats:
1. Console output - Summary of findings
2. JSON files - Detailed scan results

JSON reports are saved:
- Locally: In the `reports/` directory
- Cloud: In the GCS bucket (if configured) under `github_scanner/{scan_type}/{filename}`

## License

[MIT License](LICENSE)