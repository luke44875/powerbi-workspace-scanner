# Quick Setup for PowerBI Admin User

Since you're a PowerBI admin, you can run this with interactive authentication - no service principal setup needed!

## Prerequisites

✅ You have PowerBI Admin or Fabric Administrator role
✅ Python 3.8+ installed

## Setup Steps

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Find Your Tenant ID

**Option A: Using Azure CLI (if installed)**
```bash
az account show --query tenantId -o tsv
```

**Option B: Using Azure Portal**
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **Properties**
3. Copy the **Tenant ID**

**Option C: Using PowerBI**
1. Go to [PowerBI Admin Portal](https://app.powerbi.com/admin-portal)
2. The tenant ID is in the URL after `/tenants/`

### 3. Configure the Script

**Option A: Environment Variable (Recommended)**
```bash
export AZURE_TENANT_ID="your-tenant-id-here"
```

**Option B: Edit the Script**
Open `powerbi_workspace_scanner.py` and replace:
```python
TENANT_ID = "YOUR_TENANT_ID"
```
with:
```python
TENANT_ID = "your-actual-tenant-id"
```

### 4. Run the Scanner

```bash
python powerbi_workspace_scanner.py
```

## What Happens When You Run It

1. **Authentication**: A browser window will open asking you to sign in with your admin account
2. **Scanning**: The script will scan all workspaces in batches (this may take several minutes for large tenants)
3. **Export**: Results will be saved as timestamped CSV and Excel files

## Expected Output

```
PowerBI Workspace Scanner
==================================================
Authentication: Interactive
API Mode: Admin API

Step 1: Authenticating...
✓ Authentication successful

Step 2: Scanning workspaces...
Note: Using Admin API - this may take several minutes for large tenants
The scanner will process workspaces in batches to avoid API limits
✓ Scanned 245 workspace/report combinations

Step 3: Exporting results...
✓ Exported to CSV: powerbi_workspace_scan_20240101_143022.csv
✓ Exported to Excel: powerbi_workspace_scan_20240101_143022.xlsx
```

## Troubleshooting

**Browser doesn't open for authentication:**
- The script will show a URL to copy/paste into your browser
- Sign in with your admin account

**"Insufficient permissions" error:**
- Make sure you're signed in with your PowerBI admin account
- Check that your account has PowerBI Admin or Fabric Administrator role

**Rate limiting messages:**
- This is normal for large tenants
- The script automatically handles this - just wait

## Files Generated

The scanner creates two files with timestamps:
- **CSV file**: For data analysis and importing to other tools
- **Excel file**: Formatted version with proper column widths

Both files contain the same data with all the columns you requested:
- Workspace Name, Owner, ID, Permissions
- Report Names, IDs, Owner, Permissions
- Linked Service Principals

---

That's it! Much simpler than service principal setup. Just set your tenant ID and run the script.