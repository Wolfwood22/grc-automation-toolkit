from narrative import generate

SAMPLE_FINDINGS = {
"iam": [
{"username": "alice", "finding_type": "stale_account", "severity":
"Medium", "detail": "127 days"},
{"username": "bob", "finding_type": "admin_without_mfa", "severity": "High", "detail": "No MFA"},
],
"access_analyzer": [
{"resource_type": "AWS::S3::Bucket", "resource_arn": "arn:aws:s3:::bucket",
"principal": "*", "access_level": "s3:GetObject", "severity": "High"}, ], "security_hub": [
{"control_id": "IAM.1", "title": "Full admin", "severity": "High",
"remediation": "Fix it."},
],
}


def test_returns_non_empty_string():
    result = generate(SAMPLE_FINDINGS)
    assert isinstance(result, str) and len(result) > 50


def test_narrative_contains_total_count():
    result = generate(SAMPLE_FINDINGS)
    assert "4" in result


def test_narrative_contains_high_count():
    result = generate(SAMPLE_FINDINGS)
    assert "3" in result


def test_empty_findings_returns_string():
    result = generate({"iam": [], "access_analyzer": [], "security_hub": []})
    assert isinstance(result, str)