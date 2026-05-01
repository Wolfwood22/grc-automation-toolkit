import boto3

IAM_CONTROLS = [f"IAM.{i}" for i in range(1, 10)]


def collect(hub_client=None):
    if hub_client is None:
        hub_client = boto3.client("securityhub")

    findings = []
    paginator = hub_client.get_paginator("get_findings")
    filters = { "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        "ComplianceSecurityControlId": [
            {"Value": ctrl, "Comparison": "EQUALS"} for ctrl in IAM_CONTROLS
        ],
    }

    for page in paginator.paginate(Filters=filters):
        for f in page["Findings"]:
            findings.append({ "control_id": f.get("Compliance", {}).get("SecurityControlId", "Unknown"),
                "title": f.get("Title", "Unknown"), "severity": f.get("Severity", {}).get("Label","MEDIUM").capitalize(),
                "remediation": (
                    f.get("Remediation", {})
                    .get("Recommendation", {})
                    .get("Text", "See Security Hub for details")
    ),
            })

    return findings