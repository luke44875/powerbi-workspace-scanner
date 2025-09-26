# PowerBI Workspace Scanner

A comprehensive Python tool to scan all PowerBI workspaces in your tenant and generate detailed reports with workspace information, reports, datasets, permissions, and service principals.

## Features

- ✅ Scans all workspaces in your PowerBI tenant
- ✅ Extracts workspace metadata (name, owner, ID, permissions)
- ✅ Lists all reports within each workspace
- ✅ Identifies report owners and permissions
- ✅ Detects linked service principals
- ✅ Handles both legacy and modern reports
- ✅ Exports results to CSV and Excel formats
- ✅ Supports both Service Principal and Interactive authentication
- ✅ Admin API integration for comprehensive data
- ✅ Rate limiting and batch processing for large tenants

## Output Columns

The scanner generates a table with the following columns:

| Column | Description |
|--------|-------------|
| Workspace Name | Name of the PowerBI workspace |
| Workspace Owner | Primary owner/admin of the workspace |
| Workspace ID | Unique identifier for the workspace |
| Workspace Permissions | List of all users/groups and their permissions |
| Report Names | Names of reports in the workspace |
| Report IDs | Unique identifiers for reports |
| Report Owner | Owner of the specific report |
| Report Permissions | Permissions specific to the report |
| Linked Service Principals | Service principals with access |

## Prerequisites

### PowerBI Permissions

For **full functionality** (recommended):
- PowerBI Admin role or Fabric Administrator role
- Service Principal with admin permissions
- "Allow service principals to use read-only admin APIs" enabled in PowerBI Admin Portal

For **limited functionality**:
- Regular PowerBI user account
- Access only to workspaces you're a member of

### Azure AD App Registration (Service Principal)

1. Register a new application in Azure AD
2. Note the **Application (client) ID** and **Directory (tenant) ID**
3. Create a **client secret**
4. Add PowerBI Service permissions:
   - `Dataset.Read.All`
   - `Report.Read.All`
   - `Workspace.Read.All`
   - `Tenant.Read.All` (for admin operations)

### PowerBI Admin Portal Configuration

1. Go to PowerBI Admin Portal → Tenant settings
2. Enable "Allow service principals to use read-only admin APIs"
3. Add your service principal to the security group
4. Enable "Enhance admin APIs responses with detailed metadata"

## Installation

1. Clone or download the script files
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

### Method 1: Environment Variables (Recommended)

Set the following environment variables:

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export USE_ADMIN_API="true"  # Optional, default: true
```

### Method 2: Direct Script Configuration

Edit the configuration section in `powerbi_workspace_scanner.py`:

```python
TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
USE_SERVICE_PRINCIPAL = True
USE_ADMIN_API = True
```

## Usage

### Basic Usage

```bash
python powerbi_workspace_scanner.py
```

### Interactive Authentication

If you prefer to use interactive browser authentication instead of a service principal:

```python
USE_SERVICE_PRINCIPAL = False
```

### Limited Permissions Mode

If you don't have admin permissions, set:

```python
USE_ADMIN_API = False
```

Note: This will provide limited information compared to the admin API.

## Output Files

The scanner generates timestamped files:

- `powerbi_workspace_scan_YYYYMMDD_HHMMSS.csv` - CSV format for data analysis
- `powerbi_workspace_scan_YYYYMMDD_HHMMSS.xlsx` - Excel format with formatting

## Sample Output

```
PowerBI Workspace Scanner
==================================================
Authentication: Service Principal
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

==================================================
SCAN COMPLETE
==================================================
Total records processed: 245
```

## Rate Limits

The scanner respects PowerBI API limits:
- Maximum 500 requests per hour
- Maximum 16 concurrent requests
- Automatic retry with backoff for rate limiting

## Troubleshooting

### Common Issues

**Authentication Errors:**
- Verify your tenant ID, client ID, and client secret
- Ensure the service principal is registered in Azure AD
- Check that the service principal has required PowerBI permissions

**Permission Errors:**
- Verify admin permissions in PowerBI Admin Portal
- Enable "Allow service principals to use read-only admin APIs"
- Add service principal to the appropriate security group

**Limited Data:**
- Some information requires admin API access
- If you see "Limited access - Admin API required", enable admin permissions
- Regular users can only see workspaces they have access to

**Rate Limiting:**
- Large tenants may take considerable time to scan
- The scanner automatically handles rate limits
- Consider running during off-peak hours

### API Permissions Required

**For Admin API (Full Access):**
```
Dataset.Read.All
Report.Read.All
Workspace.Read.All
Tenant.Read.All
```

**For Regular API (Limited Access):**
```
Dataset.Read.All
Report.Read.All
Workspace.Read.All
```

## Technical Details

### Batch Processing

The scanner processes workspaces in batches of 100 to avoid API timeouts and respect rate limits. This is automatically handled.

### Data Structure

Each row in the output represents either:
- A workspace with no reports (empty report fields)
- A workspace-report combination (one row per report)

### Service Principal Detection

The scanner identifies service principals by:
- `principalType` = "App"
- Identifiers containing "service" (case-insensitive)

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is provided as-is for organizational use in scanning PowerBI workspaces.