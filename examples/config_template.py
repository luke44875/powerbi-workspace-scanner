#!/usr/bin/env python3
"""
PowerBI Scanner Configuration Template
Copy this file and customize for your environment
"""

# Your Azure AD Tenant ID
TENANT_ID = "your-tenant-id-here"

# Authentication Settings
USE_SERVICE_PRINCIPAL = False  # Set to True for automated runs
USE_ADMIN_API = True          # Set to False if you don't have admin permissions

# Service Principal Settings (only needed if USE_SERVICE_PRINCIPAL = True)
CLIENT_ID = "your-client-id-here"
CLIENT_SECRET = "your-client-secret-here"

# Scanning Options
BATCH_SIZE = 100              # Number of workspaces per batch
MAX_WAIT_MINUTES = 30         # Maximum time to wait for scan completion

# Output Settings
OUTPUT_PREFIX = "powerbi_workspace_scan"
CREATE_CSV = True
CREATE_EXCEL = True