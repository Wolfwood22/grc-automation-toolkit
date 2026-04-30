from unittest.mock import MagicMock
from access_analyzer import collect


def _mock_client(findings_list=None, analyzers=None):
    client = MagicMock()
    client.list_analyzers.return_value = {
        "analyzers": analyzers or [{"arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/demo"}]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = [{"findings": findings_list or []}]
    client.get_paginator.return_value = paginator
    return client


def test_returns_empty_when_no_analyzers():
    assert collect(analyzer_client=_mock_client(analyzers=[])) == []


def test_public_finding_is_high_severity():
    raw = [{
        "resourceType": "AWS::S3::Bucket",
        "resource": "arn:aws:s3:::my-bucket",
        "principal": {"AWS": "*"},
        "action": ["s3:GetObject"],
        "isPublic": True,
    }]
    findings = collect(analyzer_client=_mock_client(findings_list=raw))
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["resource_type"] == "AWS::S3::Bucket"


def test_non_public_finding_is_medium_severity():
    raw = [{
        "resourceType": "AWS::IAM::Role",
        "resource": "arn:aws:iam::123:role/demo",
        "principal": {"AWS": "arn:aws:iam::999:root"},
        "action": ["sts:AssumeRole"],
        "isPublic": False,
    }]
    findings = collect(analyzer_client=_mock_client(findings_list=raw))
    assert findings[0]["severity"] == "Medium"


def test_returns_required_keys():
    raw = [{
        "resourceType": "AWS::S3::Bucket",
        "resource": "arn:aws:s3:::my-bucket",
        "principal": {"AWS": "*"},
        "action": ["s3:GetObject"],
        "isPublic": True,
    }]
    finding = collect(analyzer_client=_mock_client(findings_list=raw))[0]
    for key in ("resource_type", "resource_arn", "principal", "access_level", "severity"):
        assert key in finding
