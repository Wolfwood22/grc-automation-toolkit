import boto3
import json
import csv
from datetime import datetime, timezone
from collections import defaultdict

def get_security_hub_client(region="us-east-1"):
    """Create and return a Security Hub client."""
    try:
        client = boto3.client("securityhub", region_name=region)
        return client
    except Exception as e:
        print(f"Failed to connect to Security Hub: {e}")
        raise
if __name__ == "__main__":
    client = get_security_hub_client()
    print("Connected to Security Hub successfully")
    
def get_findings(client=None, max_results=200):
    """Return mock Security Hub findings for testing."""
    return [
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789:finding/001",
            "Title": "S3 bucket public read access enabled",
            "Severity": {"Label": "CRITICAL"},
            "Compliance": {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "CreatedAt": "2026-04-01T10:00:00Z",
            "UpdatedAt": "2026-04-20T10:00:00Z",
            "Resources": [{"Type": "AwsS3Bucket", "Id": "my-data-bucket"}],
            "ProductName": "Security Hub",
            "Description": "S3 bucket allows public read access which may expose sensitive data."
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789:finding/002",
            "Title": "MFA not enabled for root account",
            "Severity": {"Label": "CRITICAL"},
            "Compliance": {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "CreatedAt": "2026-03-15T08:00:00Z",
            "UpdatedAt": "2026-04-18T08:00:00Z",
            "Resources": [{"Type": "AwsAccount", "Id": "123456789"}],
            "ProductName": "Security Hub",
            "Description": "Root account does not have MFA enabled."
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789:finding/003",
            "Title": "CloudTrail not enabled in all regions",
            "Severity": {"Label": "HIGH"},
            "Compliance": {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "CreatedAt": "2026-04-10T12:00:00Z",
            "UpdatedAt": "2026-04-10T12:00:00Z",
            "Resources": [{"Type": "AwsCloudTrailTrail", "Id": "my-trail"}],
            "ProductName": "Security Hub",
            "Description": "CloudTrail is not enabled in all regions, leaving activity unlogged."
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789:finding/004",
            "Title": "IAM password policy does not require symbols",
            "Severity": {"Label": "MEDIUM"},
            "Compliance": {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "CreatedAt": "2026-04-05T09:00:00Z",
            "UpdatedAt": "2026-04-05T09:00:00Z",
            "Resources": [{"Type": "AwsIamPasswordPolicy", "Id": "password-policy"}],
            "ProductName": "Security Hub",
            "Description": "IAM password policy does not require at least one symbol character."
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789:finding/005",
            "Title": "EC2 instance in public subnet",
            "Severity": {"Label": "LOW"},
            "Compliance": {"Status": "WARNING"},
            "WorkflowState": "NEW",
            "CreatedAt": "2026-04-12T14:00:00Z",
            "UpdatedAt": "2026-04-12T14:00:00Z",
            "Resources": [{"Type": "AwsEc2Instance", "Id": "i-0abc123"}],
            "ProductName": "Security Hub",
            "Description": "EC2 instance is deployed in a public subnet."
        }
    ]
def parse_findings(raw_findings):
    parsed = []
    for finding in raw_findings:
        severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
        compliance_status = finding.get("Compliance", {}).get("Status", "UNKNOWN")
        resources = finding.get("Resources", [])
        resource_type = resources[0].get("Type", "Unknown") if resources else "Unknown"
        resource_id = resources[0].get("Id", "Unknown") if resources else "Unknown"
        parsed.append({
            "finding_id": finding.get("Id", "")[-20:],
            "title": finding.get("Title", "No title"),
            "severity": severity,
            "compliance_status": compliance_status,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "description": finding.get("Description", "")[:200],
            "created_at": finding.get("CreatedAt", ""),
            "updated_at": finding.get("UpdatedAt", "")
        })
    return parsed


def build_summary(findings):
    severity_counts = defaultdict(int)
    status_counts = defaultdict(int)
    for f in findings:
        severity_counts[f["severity"]] += 1
        status_counts[f["compliance_status"]] += 1
    total = len(findings)
    failed = status_counts.get("FAILED", 0)
    passed = status_counts.get("PASSED", 0)
    compliance_pct = round((passed / total * 100), 1) if total > 0 else 0
    return {
        "total_findings": total,
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "informational": severity_counts.get("INFORMATIONAL", 0),
        "failed": failed,
        "passed": passed,
        "compliance_percentage": compliance_pct
    }


def write_report(findings, summary, output_file="security_hub_report.csv"):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["AWS Security Hub Compliance Report"])
        writer.writerow(["Generated:", timestamp])
        writer.writerow([])
        writer.writerow(["SUMMARY"])
        writer.writerow(["Total Findings", summary["total_findings"]])
        writer.writerow(["Critical", summary["critical"]])
        writer.writerow(["High", summary["high"]])
        writer.writerow(["Medium", summary["medium"]])
        writer.writerow(["Low", summary["low"]])
        writer.writerow(["Failed Controls", summary["failed"]])
        writer.writerow(["Compliance %", f"{summary['compliance_percentage']}%"])
        writer.writerow([])
        writer.writerow(["FINDINGS DETAIL"])
        headers = ["Finding ID", "Title", "Severity", "Status",
                   "Resource Type", "Resource ID", "Description", "Created", "Updated"]
        writer.writerow(headers)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 5))
        for f in sorted_findings:
            writer.writerow([
                f["finding_id"], f["title"], f["severity"], f["compliance_status"],
                f["resource_type"], f["resource_id"], f["description"],
                f["created_at"], f["updated_at"]
            ])
    print(f"Report written to {output_file}")
    return output_file


if __name__ == "__main__":
    print("Starting Security Hub compliance extraction...")
    
    client = get_security_hub_client()
    raw_findings = get_findings(client)
    findings = parse_findings(raw_findings)
    summary = build_summary(findings)
    
    print("\n--- SUMMARY ---")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    
    output_file = f"security_hub_report_{datetime.now().strftime('%Y%m%d')}.csv"
    write_report(findings, summary, output_file)
    print(f"\nDone. Open {output_file} to review.")