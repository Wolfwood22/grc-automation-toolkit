from unittest.mock import MagicMock
from xmlrpc import client
from security_hub import collect


def _mock_client(findings_list=None):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Findings": findings_list or []}]
    client.get_paginator.return_value = paginator
    return client


def test_returns_empty_with_no_findings():
    assert collect(hub_client=_mock_client([])) == []


def test_maps_finding_fields():
    raw = [{
        "Compliance": {"SecurityControlId": "IAM.1"},
        "Title": "IAM policies should not allow full admin",
        "Severity": {"Label": "HIGH"},
        "Remediation": {"Recommendation": {"Text": "Remove full admin policies."}},
}]
    finding = collect(hub_client=_mock_client(raw))[0]
    assert finding["control_id"] == "IAM.1"
    assert finding["severity"] == "High"
    assert finding["title"] == "IAM policies should not allow full admin"
    assert finding["remediation"] == "Remove full admin policies."


def test_missing_remediation_defaults_gracefully():
    raw = [{
        "Compliance": {"SecurityControlId": "IAM.5"},
        "Title": "MFA not enabled",
        "Severity": {"Label": "MEDIUM"},
        }]
    finding = collect(hub_client=_mock_client(raw))[0]
    assert finding["remediation"] == "See Security Hub for details"


def test_returns_required_keys():
    raw = [{
        "Compliance": {"SecurityControlId": "IAM.1"},
        "Title": "Test",
        "Severity": {"Label": "HIGH"},
    }]
    finding = collect(hub_client=_mock_client(raw))[0]
    for key in ("control_id", "title", "severity", "remediation"):
        assert key in finding