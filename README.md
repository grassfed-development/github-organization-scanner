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
- Google Cloud SDK (for GCP