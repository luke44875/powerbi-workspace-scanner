#!/usr/bin/env python3
"""
PowerBI Workspace Scanner
Scans all PowerBI workspaces and generates a comprehensive report with workspace and report details.
"""

import os
import json
import time
import requests
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

try:
    from azure.identity import ClientSecretCredential, InteractiveBrowserCredential
except ImportError:
    print("Azure Identity library not found. Please install: pip install azure-identity")
    exit(1)

class PowerBIScanner:
    def __init__(self, tenant_id: str, client_id: str = None, client_secret: str = None, use_service_principal: bool = True):
        """
        Initialize PowerBI Scanner

        Args:
            tenant_id: Azure AD Tenant ID
            client_id: Application (client) ID for service principal
            client_secret: Client secret for service principal
            use_service_principal: If True, use service principal auth, else interactive
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_service_principal = use_service_principal
        self.base_url = "https://api.powerbi.com/v1.0/myorg"
        self.admin_url = "https://api.powerbi.com/v1.0/myorg/admin"
        self.access_token = None

        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

        # Rate limiting
        self.max_requests_per_hour = 500
        self.max_concurrent_requests = 16
        self.request_count = 0
        self.start_time = datetime.now()

    def authenticate(self) -> str:
        """
        Authenticate and get access token

        Returns:
            Access token string
        """
        scope = "https://analysis.windows.net/powerbi/api/.default"

        try:
            if self.use_service_principal and self.client_id and self.client_secret:
                self.logger.info("Authenticating with service principal...")
                credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
            else:
                self.logger.info("Authenticating with interactive browser...")
                credential = InteractiveBrowserCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id if self.client_id else "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # PowerBI CLI default
                )

            token = credential.get_token(scope)
            self.access_token = token.token
            self.logger.info("Authentication successful")
            return self.access_token

        except Exception as e:
            self.logger.error(f"Authentication failed: {str(e)}")
            raise

    def _make_request(self, url: str, method: str = 'GET', data: Dict = None) -> Dict:
        """
        Make authenticated API request with rate limiting

        Args:
            url: API endpoint URL
            method: HTTP method (GET, POST)
            data: Request payload for POST requests

        Returns:
            JSON response
        """
        # Check rate limits
        elapsed_hours = (datetime.now() - self.start_time).total_seconds() / 3600
        if elapsed_hours >= 1:
            self.request_count = 0
            self.start_time = datetime.now()

        if self.request_count >= self.max_requests_per_hour:
            self.logger.warning("Rate limit reached, waiting 1 hour...")
            time.sleep(3600)
            self.request_count = 0
            self.start_time = datetime.now()

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        try:
            if method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=data)
            else:
                response = requests.get(url, headers=headers)

            self.request_count += 1

            if response.status_code == 429:  # Too Many Requests
                retry_after = int(response.headers.get('Retry-After', 60))
                self.logger.warning(f"Rate limited, waiting {retry_after} seconds...")
                time.sleep(retry_after)
                return self._make_request(url, method, data)

            response.raise_for_status()
            return response.json() if response.content else {}

        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {url} - {str(e)}")
            if response.status_code == 401:
                self.logger.info("Token expired, re-authenticating...")
                self.authenticate()
                return self._make_request(url, method, data)
            raise

    def get_all_workspaces(self) -> List[Dict]:
        """
        Get all workspaces using regular API (non-admin)

        Returns:
            List of workspace dictionaries
        """
        self.logger.info("Getting all workspaces...")
        url = f"{self.base_url}/groups"

        try:
            response = self._make_request(url)
            workspaces = response.get('value', [])
            self.logger.info(f"Found {len(workspaces)} workspaces")
            return workspaces
        except Exception as e:
            self.logger.error(f"Failed to get workspaces: {str(e)}")
            return []

    def trigger_workspace_scan(self, workspace_ids: List[str] = None) -> str:
        """
        Trigger admin API workspace scan

        Args:
            workspace_ids: List of workspace IDs to scan (None for all)

        Returns:
            Scan ID
        """
        self.logger.info("Triggering workspace scan...")
        url = f"{self.admin_url}/workspaces/getInfo"

        payload = {
            "workspaces": workspace_ids if workspace_ids else [],
            "getArtifactUsers": True,
            "datasetSchema": False,  # Set to True if you need detailed schema info
            "datasetExpressions": False,  # Set to True if you need DAX expressions
            "lineage": True
        }

        try:
            response = self._make_request(url, 'POST', payload)
            scan_id = response.get('id')
            self.logger.info(f"Scan triggered with ID: {scan_id}")
            return scan_id
        except Exception as e:
            self.logger.error(f"Failed to trigger scan: {str(e)}")
            raise

    def check_scan_status(self, scan_id: str) -> str:
        """
        Check the status of a workspace scan

        Args:
            scan_id: Scan ID from trigger_workspace_scan

        Returns:
            Scan status ('NotStarted', 'Running', 'Succeeded', 'Failed')
        """
        url = f"{self.admin_url}/workspaces/scanStatus/{scan_id}"

        try:
            response = self._make_request(url)
            status = response.get('status', 'Unknown')
            return status
        except Exception as e:
            self.logger.error(f"Failed to check scan status: {str(e)}")
            return 'Failed'

    def get_scan_result(self, scan_id: str) -> Dict:
        """
        Get the results of a completed workspace scan

        Args:
            scan_id: Scan ID from trigger_workspace_scan

        Returns:
            Scan results dictionary
        """
        url = f"{self.admin_url}/workspaces/scanResult/{scan_id}"

        try:
            response = self._make_request(url)
            return response
        except Exception as e:
            self.logger.error(f"Failed to get scan results: {str(e)}")
            return {}

    def wait_for_scan_completion(self, scan_id: str, max_wait_minutes: int = 30) -> bool:
        """
        Wait for scan to complete with polling

        Args:
            scan_id: Scan ID
            max_wait_minutes: Maximum time to wait in minutes

        Returns:
            True if completed successfully, False otherwise
        """
        start_time = datetime.now()
        max_wait_seconds = max_wait_minutes * 60

        self.logger.info(f"Waiting for scan {scan_id} to complete...")

        while (datetime.now() - start_time).total_seconds() < max_wait_seconds:
            status = self.check_scan_status(scan_id)
            self.logger.info(f"Scan status: {status}")

            if status == 'Succeeded':
                return True
            elif status == 'Failed':
                self.logger.error("Scan failed")
                return False

            time.sleep(30)  # Wait 30 seconds between checks

        self.logger.error(f"Scan timed out after {max_wait_minutes} minutes")
        return False

    def get_workspace_users(self, workspace_id: str) -> List[Dict]:
        """
        Get users and permissions for a specific workspace

        Args:
            workspace_id: Workspace ID

        Returns:
            List of user dictionaries with permissions
        """
        url = f"{self.base_url}/groups/{workspace_id}/users"

        try:
            response = self._make_request(url)
            return response.get('value', [])
        except Exception as e:
            self.logger.warning(f"Could not get users for workspace {workspace_id}: {str(e)}")
            return []

    def process_workspace_data(self, scan_results: Dict) -> List[Dict]:
        """
        Process scan results and extract structured data

        Args:
            scan_results: Results from workspace scan

        Returns:
            List of processed workspace/report records
        """
        processed_data = []
        workspaces = scan_results.get('workspaces', [])

        self.logger.info(f"Processing {len(workspaces)} workspaces from scan results...")

        for workspace in workspaces:
            workspace_info = self._extract_workspace_info(workspace)
            reports = workspace.get('reports', [])

            if not reports:
                # Add workspace entry even if no reports
                processed_data.append({
                    **workspace_info,
                    'Report Names': '',
                    'Report IDs': '',
                    'Report Owner': '',
                    'Report Permissions': ''
                })
            else:
                # Add entry for each report
                for report in reports:
                    report_info = self._extract_report_info(report, workspace.get('id'))
                    processed_data.append({
                        **workspace_info,
                        **report_info
                    })

        return processed_data

    def _extract_workspace_info(self, workspace: Dict) -> Dict:
        """
        Extract workspace information from scan data

        Args:
            workspace: Workspace data from scan

        Returns:
            Dictionary with workspace information
        """
        # Get workspace users/permissions
        users = workspace.get('users', [])
        workspace_permissions = []
        workspace_owner = ''
        service_principals = []

        for user in users:
            user_type = user.get('principalType', 'User')
            identifier = user.get('emailAddress', user.get('identifier', ''))
            access_right = user.get('accessRight', '')

            if user_type == 'App' or 'service' in identifier.lower():
                service_principals.append(f"{identifier} ({access_right})")

            permission_str = f"{identifier} ({access_right})"
            workspace_permissions.append(permission_str)

            if access_right == 'Admin' and not workspace_owner:
                workspace_owner = identifier

        return {
            'Workspace Name': workspace.get('name', ''),
            'Workspace Owner': workspace_owner,
            'Workspace ID': workspace.get('id', ''),
            'Workspace Permissions': '; '.join(workspace_permissions),
            'Linked Service Principals': '; '.join(service_principals)
        }

    def _extract_report_info(self, report: Dict, workspace_id: str) -> Dict:
        """
        Extract report information from scan data

        Args:
            report: Report data from scan
            workspace_id: Parent workspace ID

        Returns:
            Dictionary with report information
        """
        # Get report users/permissions
        users = report.get('users', [])
        report_permissions = []
        report_owner = ''

        for user in users:
            identifier = user.get('emailAddress', user.get('identifier', ''))
            access_right = user.get('accessRight', '')

            permission_str = f"{identifier} ({access_right})"
            report_permissions.append(permission_str)

            if access_right in ['Owner', 'Admin'] and not report_owner:
                report_owner = identifier

        # Try to get more detailed report info
        report_created_by = report.get('createdBy', '')
        if not report_owner and report_created_by:
            report_owner = report_created_by

        return {
            'Report Names': report.get('name', ''),
            'Report IDs': report.get('id', ''),
            'Report Owner': report_owner,
            'Report Permissions': '; '.join(report_permissions)
        }

    def get_modified_workspaces(self, modified_since: datetime = None) -> List[str]:
        """
        Get list of workspaces modified since a specific time

        Args:
            modified_since: DateTime to check modifications since

        Returns:
            List of workspace IDs
        """
        url = f"{self.admin_url}/workspaces/modified"

        if modified_since:
            params = {'modifiedSince': modified_since.isoformat()}
            url += f"?modifiedSince={modified_since.isoformat()}"

        try:
            response = self._make_request(url)
            workspaces = response.get('workspaces', [])
            return [ws.get('id') for ws in workspaces if ws.get('id')]
        except Exception as e:
            self.logger.warning(f"Could not get modified workspaces: {str(e)}")
            return []

    def scan_all_workspaces(self, use_admin_api: bool = True, batch_size: int = 100) -> List[Dict]:
        """
        Main method to scan all workspaces and return structured data

        Args:
            use_admin_api: Whether to use admin API for comprehensive scan
            batch_size: Number of workspaces to process per batch

        Returns:
            List of processed workspace/report records
        """
        all_data = []

        try:
            if use_admin_api:
                self.logger.info("Using Admin API for comprehensive workspace scan...")

                # Get all workspace IDs first
                workspaces = self.get_all_workspaces()
                workspace_ids = [ws.get('id') for ws in workspaces if ws.get('id')]

                if not workspace_ids:
                    self.logger.warning("No workspaces found or insufficient permissions")
                    return []

                # Process in batches
                for i in range(0, len(workspace_ids), batch_size):
                    batch_ids = workspace_ids[i:i + batch_size]
                    self.logger.info(f"Processing batch {i // batch_size + 1}: {len(batch_ids)} workspaces")

                    # Trigger scan for this batch
                    scan_id = self.trigger_workspace_scan(batch_ids)

                    # Wait for completion
                    if self.wait_for_scan_completion(scan_id):
                        # Get and process results
                        scan_results = self.get_scan_result(scan_id)
                        batch_data = self.process_workspace_data(scan_results)
                        all_data.extend(batch_data)
                        self.logger.info(f"Processed {len(batch_data)} records from batch")
                    else:
                        self.logger.error(f"Scan failed for batch {i // batch_size + 1}")

            else:
                self.logger.info("Using regular API (limited data available)...")
                workspaces = self.get_all_workspaces()

                for workspace in workspaces:
                    workspace_info = {
                        'Workspace Name': workspace.get('name', ''),
                        'Workspace Owner': workspace.get('createdBy', ''),  # Limited info
                        'Workspace ID': workspace.get('id', ''),
                        'Workspace Permissions': 'Limited access - Admin API required',
                        'Linked Service Principals': 'Limited access - Admin API required',
                        'Report Names': 'Limited access - Admin API required',
                        'Report IDs': 'Limited access - Admin API required',
                        'Report Owner': 'Limited access - Admin API required',
                        'Report Permissions': 'Limited access - Admin API required'
                    }
                    all_data.append(workspace_info)

        except Exception as e:
            self.logger.error(f"Error during workspace scan: {str(e)}")
            raise

        return all_data

    def export_to_files(self, data: List[Dict], output_prefix: str = "powerbi_workspace_scan") -> Dict[str, str]:
        """
        Export data to CSV and Excel files

        Args:
            data: Processed workspace data
            output_prefix: Prefix for output filenames

        Returns:
            Dictionary with file paths
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"{output_prefix}_{timestamp}.csv"
        excel_filename = f"{output_prefix}_{timestamp}.xlsx"

        file_paths = {}

        try:
            # Create DataFrame
            df = pd.DataFrame(data)

            # Reorder columns to match requested format
            column_order = [
                'Workspace Name', 'Workspace Owner', 'Workspace ID', 'Workspace Permissions',
                'Report Names', 'Report IDs', 'Report Owner', 'Report Permissions',
                'Linked Service Principals'
            ]

            # Only include columns that exist in the data
            existing_columns = [col for col in column_order if col in df.columns]
            df = df[existing_columns]

            # Export to CSV
            df.to_csv(csv_filename, index=False, encoding='utf-8-sig')
            file_paths['csv'] = os.path.abspath(csv_filename)
            self.logger.info(f"Exported to CSV: {csv_filename}")

            # Export to Excel
            with pd.ExcelWriter(excel_filename, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name='PowerBI Workspaces', index=False)

                # Format the Excel file
                workbook = writer.book
                worksheet = writer.sheets['PowerBI Workspaces']

                # Add header formatting
                header_format = workbook.add_format({
                    'bold': True,
                    'text_wrap': True,
                    'valign': 'top',
                    'fg_color': '#D7E4BC',
                    'border': 1
                })

                for col_num, value in enumerate(df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                    worksheet.set_column(col_num, col_num, 20)  # Set column width

            file_paths['excel'] = os.path.abspath(excel_filename)
            self.logger.info(f"Exported to Excel: {excel_filename}")

            # Print summary
            self.logger.info(f"Export complete:")
            self.logger.info(f"  Total records: {len(df)}")
            self.logger.info(f"  Total columns: {len(df.columns)}")
            self.logger.info(f"  Files created:")
            self.logger.info(f"    - {csv_filename}")
            self.logger.info(f"    - {excel_filename}")

        except Exception as e:
            self.logger.error(f"Error exporting data: {str(e)}")
            raise

        return file_paths


def main():
    """Main execution function"""
    # Configuration for Interactive Admin Authentication
    TENANT_ID = "6267379f-7bab-4fc9-b4f2-7ce573e7f9b4"  # Your organization's tenant ID
    CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # PowerBI CLI default client ID
    CLIENT_SECRET = None  # Not needed for interactive auth
    USE_SERVICE_PRINCIPAL = False  # Using interactive authentication
    USE_ADMIN_API = True  # You have admin permissions
    BATCH_SIZE = 100  # Number of workspaces to process per batch

    # You can also use environment variables
    TENANT_ID = os.getenv('AZURE_TENANT_ID', TENANT_ID)
    CLIENT_ID = os.getenv('AZURE_CLIENT_ID', CLIENT_ID)
    USE_ADMIN_API = os.getenv('USE_ADMIN_API', str(USE_ADMIN_API)).lower() == 'true'

    print("PowerBI Workspace Scanner")
    print("=" * 50)
    print(f"Authentication: {'Service Principal' if USE_SERVICE_PRINCIPAL else 'Interactive'}")
    print(f"API Mode: {'Admin API' if USE_ADMIN_API else 'Regular API (Limited)'}")
    print()

    if TENANT_ID == "YOUR_TENANT_ID":
        print("Error: Please configure your TENANT_ID")
        print("You can either:")
        print("  1. Set environment variable: export AZURE_TENANT_ID='your-tenant-id'")
        print("  2. Update TENANT_ID in the script")
        print("\nTo find your tenant ID:")
        print("  - Go to Azure Portal → Azure Active Directory → Properties")
        print("  - Or run: az account show --query tenantId -o tsv")
        exit(1)

    # Create scanner instance
    scanner = PowerBIScanner(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        use_service_principal=USE_SERVICE_PRINCIPAL
    )

    try:
        # Step 1: Authenticate
        print("Step 1: Authenticating...")
        scanner.authenticate()
        print("✓ Authentication successful")

        # Step 2: Scan workspaces
        print("\nStep 2: Scanning workspaces...")
        if USE_ADMIN_API:
            print("Note: Using Admin API - this may take several minutes for large tenants")
            print("The scanner will process workspaces in batches to avoid API limits")

        workspace_data = scanner.scan_all_workspaces(
            use_admin_api=USE_ADMIN_API,
            batch_size=BATCH_SIZE
        )

        if not workspace_data:
            print("⚠ No workspace data retrieved. Check permissions and configuration.")
            exit(1)

        print(f"✓ Scanned {len(workspace_data)} workspace/report combinations")

        # Step 3: Export results
        print("\nStep 3: Exporting results...")
        file_paths = scanner.export_to_files(workspace_data)

        print("\n" + "=" * 50)
        print("SCAN COMPLETE")
        print("=" * 50)
        print(f"Total records processed: {len(workspace_data)}")
        print("\nOutput files:")
        if 'csv' in file_paths:
            print(f"  📄 CSV: {file_paths['csv']}")
        if 'excel' in file_paths:
            print(f"  📊 Excel: {file_paths['excel']}")

        # Show sample data
        if workspace_data:
            print(f"\nSample data (first 3 records):")
            df_sample = pd.DataFrame(workspace_data[:3])
            print(df_sample.to_string(index=False, max_colwidth=30))

        print(f"\n✓ PowerBI workspace scan completed successfully!")

    except KeyboardInterrupt:
        print("\n⚠ Scan interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n✗ Error during scan: {str(e)}")
        logging.error(f"Full error details: {str(e)}", exc_info=True)
        exit(1)


if __name__ == "__main__":
    main()