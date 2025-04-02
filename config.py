import os
import logging
from typing import List, Dict, Optional
from utils.vault_client import VaultClient
from utils.gcp_secret_client import GCPSecretClient

logger = logging.getLogger(__name__)

# Detect environment (for logging purposes)
ENV = os.environ.get('APP_ENV', 'local')

# Initialize Vault client as primary token source
vault_client = None
try:
    logger.info(f"Initializing Vault client in {ENV} environment")
    vault_client = VaultClient(
        mount_point=os.environ.get('VAULT_GITHUB_MOUNT', 'github')
    )
    if not vault_client.is_available():
        logger.warning("Vault client initialization failed, will try GCP Secret Manager")
except Exception as e:
    logger.error(f"Error initializing Vault client: {str(e)}")
    vault_client = None

# Initialize GCP Secret Manager client as secondary token source
gcp_secret_client = None
if not vault_client or not vault_client.is_available():
    try:
        logger.info(f"Initializing GCP Secret Manager client in {ENV} environment")
        gcp_secret_client = GCPSecretClient()
        if not gcp_secret_client.is_available():
            logger.warning("GCP Secret Manager client initialization failed, will fall back to environment variables")
    except Exception as e:
        logger.error(f"Error initializing GCP Secret Manager client: {str(e)}")
        gcp_secret_client = None

# Get tokens from appropriate source (Vault first, GCP Secret Manager second, environment variables as last resort)
GITHUB_TOKENS_BY_SCOPE = {}
GITHUB_TOKEN = None

# Try to get tokens from Vault first
if vault_client and vault_client.is_available():
    # Get tokens from Vault
    logger.info("Retrieving GitHub tokens from Vault")
    GITHUB_TOKENS_BY_SCOPE = vault_client.get_github_tokens()
    
    # Get single token from Vault for backward compatibility
    single_token_data = vault_client.get_secret('token')
    if single_token_data:
        GITHUB_TOKEN = single_token_data.get('value')
        logger.info("Retrieved single GitHub token from Vault")
    
    if not GITHUB_TOKENS_BY_SCOPE and not GITHUB_TOKEN:
        logger.warning("No tokens found in Vault, will try GCP Secret Manager")
elif gcp_secret_client and gcp_secret_client.is_available():
    # Get tokens from GCP Secret Manager
    logger.info("Retrieving GitHub tokens from GCP Secret Manager")
    GITHUB_TOKENS_BY_SCOPE = gcp_secret_client.get_github_tokens()
    
    # Get single token from GCP Secret Manager for backward compatibility
    GITHUB_TOKEN = gcp_secret_client.get_secret('github-token')
    if GITHUB_TOKEN:
        logger.info("Retrieved single GitHub token from GCP Secret Manager")
    
    if not GITHUB_TOKENS_BY_SCOPE and not GITHUB_TOKEN:
        logger.warning("No tokens found in GCP Secret Manager, will try environment variables")
else:
    logger.info("Vault and GCP Secret Manager not available, falling back to environment variables")

# If no tokens from Vault or GCP Secret Manager, try environment variables
if not GITHUB_TOKENS_BY_SCOPE and not GITHUB_TOKEN:
    # Get single token from environment (for backward compatibility)
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
    if GITHUB_TOKEN:
        logger.info("Using GitHub token from environment variables")
    
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
    
    # Parse tokens for each scope from environment variables
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

# Log token configuration (without exposing tokens)
vault_source = vault_client and vault_client.is_available() and (bool(GITHUB_TOKEN) or bool(GITHUB_TOKENS_BY_SCOPE))
gcp_source = gcp_secret_client and gcp_secret_client.is_available() and (bool(GITHUB_TOKEN) or bool(GITHUB_TOKENS_BY_SCOPE))
env_source = bool(GITHUB_TOKEN) or bool(GITHUB_TOKENS_BY_SCOPE)

logger.info(f"Environment: {ENV}")
if vault_source:
    logger.info("Token source: Vault")
elif gcp_source:
    logger.info("Token source: GCP Secret Manager")
else:
    logger.info("Token source: Environment variables")

logger.info(f"Single token available: {GITHUB_TOKEN is not None}")
logger.info(f"Scoped tokens: {', '.join(GITHUB_TOKENS_BY_SCOPE.keys()) if GITHUB_TOKENS_BY_SCOPE else 'None'}")
for scope, tokens in GITHUB_TOKENS_BY_SCOPE.items():
    logger.info(f"  {scope}: {len(tokens)} tokens")