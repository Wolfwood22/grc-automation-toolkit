from report import render

FINDINGS = {
    "iam": [
        {"username": "alice", "finding_type": "stale_account", "severity": "Medium", "detail": "No login in 127 days"},
        {"username": "bob", "finding_type": "admin_without_mfa", "severity": "High", "detail": "No MFA registered"},
],
"access_analyzer": [
{"resource_type": "AWS::S3::Bucket", "resource_arn": "arn:aws:s3:::demo-bucket",
"principal": "*", "access_level": "s3:GetObject", "severity": "High"},
],
"security_hub": [
{"control_id": "IAM.1", "title": "Full admin policies", "severity": "High", "remediation": "Remove full admin."},
    ],
}
NARRATIVE = "This review identified 4 findings including 3 High severity items."
ACCOUNT_ID = "123456789012"
DATE = "20260428"


def test_returns_string():
    assert isinstance(render(FINDINGS, NARRATIVE, ACCOUNT_ID, DATE), str)


def test_is_valid_html():
    result = render(FINDINGS, NARRATIVE, ACCOUNT_ID, DATE)
    assert result.strip().startswith("<!DOCTYPE html>")
    assert "</html>" in result


def test_contains_account_id():
    assert ACCOUNT_ID in render(FINDINGS, NARRATIVE, ACCOUNT_ID, DATE)


def test_contains_narrative():
    assert NARRATIVE in render(FINDINGS, NARRATIVE, ACCOUNT_ID, DATE)


def test_contains_iam_usernames():
    result = render(FINDINGS, NARRATIVE, ACCOUNT_ID, DATE)
    assert "alice" in result
    assert "bob" in result


def test_contains_all_compliance_frameworks():
    result = render(FINDINGS, NARRATIVE, ACCOUNT_ID, DATE)
    for framework in ("SOC 2", "ISO 27001", "NIST 800-53", "PCI-DSS 4.0", "CMMC"):
        assert framework in result


def test_high_findings_produce_red_badge():
    result = render(FINDINGS, NARRATIVE, ACCOUNT_ID, DATE)
    assert "High Risk" in result