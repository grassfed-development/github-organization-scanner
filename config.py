import os
from typing import List, Dict

# Single token (for backward compatibility)
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')

# Token scopes with their respective environment variable names
# Based on actual GitHub PAT scopes
TOKEN_SCOPES = {
    # Repository scopes
    "repo": "GITHUB_TOKENS_REPO",                     # Full control of private repositories
    "repo:status": "GITHUB_TOKENS_REPO_STATUS",       # Access commit status
    "repo_deployment": "GITHUB_TOKENS_REPO_DEPLOYMENT", # Access deployment status
    "public_repo": "GITHUB_TOKENS_PUBLIC_REPO",       # Access public repositories
    "repo:invite": "GITHUB_TOKENS_REPO_INVITE",       # Access repository invitations
    "security_events": "GITHUB_TOKENS_SECURITY_EVENTS", # Read and write security events
    
    # Workflow/Actions scopes
    "workflow": "GITHUB_TOKENS_WORKFLOW",             # Update GitHub Action workflows
    
    # Organization scopes
    "read:org": "GITHUB_TOKENS_READ_ORG",             # Read org and team membership, read org projects
    "admin:org": "GITHUB_TOKENS_ADMIN_ORG",           # Full control of orgs and teams
    "write:org": "GITHUB_TOKENS_WRITE_ORG",           # Read and write org and team membership
    
    # User scopes
    "read:user": "GITHUB_TOKENS_READ_USER",           # Read ALL user profile data
    
    # Runner scopes
    "manage_runners:org": "GITHUB_TOKENS_MANAGE_RUNNERS_ORG", # Manage org runners and runner groups
    
    # Copilot scopes
    "copilot": "GITHUB_TOKENS_COPILOT",               # Full control of GitHub Copilot settings
    "manage_billing:copilot": "GITHUB_TOKENS_MANAGE_BILLING_COPILOT", # View and edit Copilot Business seat assignments
}

# Dictionary to store tokens by scope
GITHUB_TOKENS_BY_SCOPE = {}

# Parse tokens for each scope
for scope, env_var in TOKEN_SCOPES.items():
    tokens_str = os.environ.get(env_var, '')
    if tokens_str:
        GITHUB_TOKENS_BY_SCOPE[scope] = [token.strip() for token in tokens_str.split(',') if token.strip()]
    else:
        GITHUB_TOKENS_BY_SCOPE[scope] = []

# All tokens combined (for backward compatibility or general use)
GITHUB_TOKENS = []
for scope, tokens in GITHUB_TOKENS_BY_SCOPE.items():
    for token in tokens:
        if token not in GITHUB_TOKENS:
            GITHUB_TOKENS.append(token)

# Add the single token to the appropriate scopes if it exists
if GITHUB_TOKEN:
    if GITHUB_TOKEN not in GITHUB_TOKENS:
        GITHUB_TOKENS.append(GITHUB_TOKEN)
    
    # Add single token to repo scope for backward compatibility
    # This is a full access token assumption - could be customized if needed
    repo_tokens = GITHUB_TOKENS_BY_SCOPE.get("repo", [])
    if GITHUB_TOKEN not in repo_tokens:
        if "repo" not in GITHUB_TOKENS_BY_SCOPE:
            GITHUB_TOKENS_BY_SCOPE["repo"] = []
        GITHUB_TOKENS_BY_SCOPE["repo"].append(GITHUB_TOKEN)

# Other configuration settings
GITHUB_ORG = os.environ.get('GITHUB_ORG')
BUCKET_NAME = os.environ.get('BUCKET_NAME')
BASE_URL = os.environ.get('BASE_URL', 'https://api.github.com')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')