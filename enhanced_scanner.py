#!/usr/bin/env python3
"""
Enhanced PowerBI Scanner - Multiple API approach to catch all reports
"""
import sys
sys.path.insert(0, '/Users/luke/Documents/Projects/PowerBi Scanner')
from powerbi_workspace_scanner import PowerBIScanner
import pandas as pd

class EnhancedPowerBIScanner(PowerBIScanner):
    def get_reports_regular_api(self) -> dict:
        """Get all reports using regular API (non-admin)"""
        try:
            url = f"{self.base_url}/reports"
            response = self._make_request(url)
            return response.get('value', [])
        except Exception as e:
            self.logger.error(f"Failed to get reports via regular API: {str(e)}")
            return []

    def get_reports_for_workspace(self, workspace_id: str) -> list:
        """Get reports for a specific workspace"""
        try:
            url = f"{self.base_url}/groups/{workspace_id}/reports"
            response = self._make_request(url)
            return response.get('value', [])
        except Exception as e:
            self.logger.warning(f"Failed to get reports for workspace {workspace_id}: {str(e)}")
            return []

    def comprehensive_scan(self):
        """Comprehensive scan using multiple approaches"""
        all_reports = {}
        all_workspaces = {}

        print("🔍 Enhanced PowerBI Scanner - Multiple API Approach")
        print("=" * 60)

        # Method 1: Regular API for reports accessible to user
        print("\n1️⃣ Scanning via Regular Reports API...")
        regular_reports = self.get_reports_regular_api()
        print(f"   Found {len(regular_reports)} reports via regular API")

        for report in regular_reports:
            report_id = report.get('id')
            if report_id:
                report['source'] = 'regular_api'
                all_reports[report_id] = report

        # Method 2: Get all workspaces and scan each individually
        print("\n2️⃣ Scanning workspaces individually...")
        workspaces = self.get_all_workspaces()
        print(f"   Found {len(workspaces)} workspaces")

        for i, workspace in enumerate(workspaces, 1):
            ws_id = workspace.get('id')
            ws_name = workspace.get('name', 'Unknown')
            all_workspaces[ws_id] = workspace

            print(f"   Scanning {i:2d}/{len(workspaces)}: {ws_name[:40]:<40}", end="")

            # Get reports for this workspace
            ws_reports = self.get_reports_for_workspace(ws_id)
            print(f" - {len(ws_reports)} reports")

            for report in ws_reports:
                report_id = report.get('id')
                if report_id:
                    if report_id in all_reports:
                        # Merge data if we already have this report
                        all_reports[report_id]['workspace_name'] = ws_name
                        all_reports[report_id]['workspace_id'] = ws_id
                    else:
                        report['source'] = 'workspace_api'
                        report['workspace_name'] = ws_name
                        report['workspace_id'] = ws_id
                        all_reports[report_id] = report

        # Method 3: Admin API scan (if available)
        print(f"\n3️⃣ Admin API comprehensive scan...")
        try:
            workspace_ids = list(all_workspaces.keys())
            scan_id = self.trigger_workspace_scan(workspace_ids)

            if self.wait_for_scan_completion(scan_id):
                scan_results = self.get_scan_result(scan_id)
                admin_report_count = 0

                for workspace in scan_results.get('workspaces', []):
                    ws_id = workspace.get('id')
                    for report in workspace.get('reports', []):
                        report_id = report.get('id')
                        admin_report_count += 1

                        if report_id:
                            if report_id in all_reports:
                                # Enhance existing report with admin data
                                all_reports[report_id].update({
                                    'admin_data': True,
                                    'users': report.get('users', []),
                                    'createdBy': report.get('createdBy'),
                                    'modifiedBy': report.get('modifiedBy'),
                                    'createdDateTime': report.get('createdDateTime'),
                                    'modifiedDateTime': report.get('modifiedDateTime')
                                })
                            else:
                                # New report found only in admin scan
                                report['source'] = 'admin_api'
                                report['workspace_id'] = ws_id
                                report['workspace_name'] = workspace.get('name', 'Unknown')
                                all_reports[report_id] = report

                print(f"   Admin API found {admin_report_count} total report entries")
            else:
                print(f"   Admin API scan failed or timed out")

        except Exception as e:
            print(f"   Admin API scan error: {str(e)}")

        # Results summary
        print(f"\n📊 COMPREHENSIVE SCAN RESULTS")
        print(f"=" * 60)
        print(f"Total unique reports found: {len(all_reports)}")
        print(f"Total workspaces: {len(all_workspaces)}")

        # Analyze by source
        source_counts = {}
        for report in all_reports.values():
            source = report.get('source', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1

        print(f"\nReports by discovery method:")
        for source, count in source_counts.items():
            print(f"  - {source}: {count}")

        # Show workspace report counts
        print(f"\nReports per workspace:")
        workspace_report_counts = {}
        for report in all_reports.values():
            ws_name = report.get('workspace_name', 'Unknown')
            workspace_report_counts[ws_name] = workspace_report_counts.get(ws_name, 0) + 1

        for ws_name, count in sorted(workspace_report_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {ws_name[:45]:<45}: {count:2d} reports")

        return list(all_reports.values()), list(all_workspaces.values())

def main():
    # Configuration
    TENANT_ID = "6267379f-7bab-4fc9-b4f2-7ce573e7f9b4"
    CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

    scanner = EnhancedPowerBIScanner(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        use_service_principal=False
    )

    try:
        # Authenticate
        scanner.authenticate()
        print("✅ Authentication successful")

        # Run comprehensive scan
        all_reports, all_workspaces = scanner.comprehensive_scan()

        # Export enhanced results
        if all_reports:
            print(f"\n💾 Exporting enhanced results...")

            # Convert to structured data
            export_data = []

            for report in all_reports:
                # Get workspace info
                ws_id = report.get('workspace_id', '')
                ws_name = report.get('workspace_name', '')

                # Extract report permissions
                users = report.get('users', [])
                report_permissions = []
                report_owner = report.get('createdBy', '')

                for user in users:
                    identifier = user.get('emailAddress', user.get('identifier', ''))
                    access_right = user.get('accessRight', '')
                    if identifier and access_right:
                        report_permissions.append(f"{identifier} ({access_right})")

                export_data.append({
                    'Workspace Name': ws_name,
                    'Workspace ID': ws_id,
                    'Report Name': report.get('name', ''),
                    'Report ID': report.get('id', ''),
                    'Report Owner': report_owner,
                    'Report Permissions': '; '.join(report_permissions),
                    'Discovery Method': report.get('source', ''),
                    'Created Date': report.get('createdDateTime', ''),
                    'Modified Date': report.get('modifiedDateTime', ''),
                    'Modified By': report.get('modifiedBy', ''),
                    'Web URL': report.get('webUrl', ''),
                    'Embed URL': report.get('embedUrl', '')
                })

            # Save to CSV
            df = pd.DataFrame(export_data)
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            filename = f"enhanced_powerbi_scan_{timestamp}.csv"
            df.to_csv(filename, index=False)

            print(f"✅ Enhanced results exported to: {filename}")
            print(f"   Total records: {len(export_data)}")
            print(f"   Total unique reports: {len(all_reports)}")

    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    main()