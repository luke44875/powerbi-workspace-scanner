#!/usr/bin/env python3
"""
Debug version of PowerBI Scanner to troubleshoot missing reports
"""
import sys
sys.path.insert(0, '/Users/luke/Documents/Projects/PowerBi Scanner')
from powerbi_workspace_scanner import PowerBIScanner
import json

def debug_scan():
    # Configuration
    TENANT_ID = "6267379f-7bab-4fc9-b4f2-7ce573e7f9b4"
    CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

    scanner = PowerBIScanner(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        use_service_principal=False
    )

    try:
        # Authenticate
        print("🔐 Authenticating...")
        scanner.authenticate()
        print("✅ Authentication successful")

        # Get basic workspace info
        print("\n📁 Getting all workspaces...")
        workspaces = scanner.get_all_workspaces()
        print(f"✅ Found {len(workspaces)} workspaces")

        # Show workspace summary
        print("\n📊 Workspace Summary:")
        for i, ws in enumerate(workspaces[:10]):  # Show first 10
            print(f"  {i+1:2d}. {ws.get('name', 'Unnamed'):<30} (ID: {ws.get('id', 'Unknown')[:8]}...)")

        if len(workspaces) > 10:
            print(f"  ... and {len(workspaces) - 10} more workspaces")

        # Try Admin API scan with detailed logging
        print(f"\n🔍 Triggering Admin API scan for all {len(workspaces)} workspaces...")
        workspace_ids = [ws.get('id') for ws in workspaces if ws.get('id')]

        scan_id = scanner.trigger_workspace_scan(workspace_ids)
        print(f"✅ Scan triggered with ID: {scan_id}")

        # Wait for completion
        print("⏳ Waiting for scan to complete...")
        if scanner.wait_for_scan_completion(scan_id):
            print("✅ Scan completed successfully")

            # Get detailed results
            scan_results = scanner.get_scan_result(scan_id)

            # Debug information
            print(f"\n🔍 Debug Information:")
            print(f"  - Workspaces in scan result: {len(scan_results.get('workspaces', []))}")

            # Analyze each workspace
            total_reports = 0
            workspaces_with_reports = 0
            workspaces_without_reports = 0

            print(f"\n📋 Detailed Workspace Analysis:")
            for ws in scan_results.get('workspaces', []):
                ws_name = ws.get('name', 'Unnamed')
                reports = ws.get('reports', [])
                datasets = ws.get('datasets', [])
                dashboards = ws.get('dashboards', [])

                report_count = len(reports)
                total_reports += report_count

                if report_count > 0:
                    workspaces_with_reports += 1
                else:
                    workspaces_without_reports += 1

                status = "📊" if report_count > 0 else "📂"
                print(f"  {status} {ws_name:<35} - Reports: {report_count:2d}, Datasets: {len(datasets):2d}, Dashboards: {len(dashboards):2d}")

                # Show report details for first few workspaces
                if report_count > 0:
                    for report in reports[:3]:  # Show first 3 reports
                        print(f"      └─ 📄 {report.get('name', 'Unnamed Report')}")
                    if len(reports) > 3:
                        print(f"      └─ ... and {len(reports) - 3} more reports")

            print(f"\n📈 Summary Statistics:")
            print(f"  - Total workspaces: {len(scan_results.get('workspaces', []))}")
            print(f"  - Workspaces with reports: {workspaces_with_reports}")
            print(f"  - Workspaces without reports: {workspaces_without_reports}")
            print(f"  - Total reports found: {total_reports}")

            # Check for potential issues
            print(f"\n🔍 Potential Issues:")
            if workspaces_without_reports > 0:
                print(f"  ⚠️  {workspaces_without_reports} workspaces have no reports")
                print(f"     This could be normal (empty workspaces) or indicate permission issues")

            # Check if any workspace names look truncated or malformed
            problematic_names = [ws.get('name', '') for ws in scan_results.get('workspaces', [])
                               if not ws.get('name') or len(ws.get('name', '')) < 2]
            if problematic_names:
                print(f"  ⚠️  Found {len(problematic_names)} workspaces with missing or very short names")

        else:
            print("❌ Scan failed or timed out")

    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    debug_scan()