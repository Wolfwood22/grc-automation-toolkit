import datetime
from unittest.mock import MagicMock
from iam_findings import collect

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _make_user(username, days_since_login=None):
    user = {
        "UserName": username,
        "UserId": "AIDAEXAMPLE123",
        "Arn": f"arn:aws:iam::123456789012:user/{username}",
        "Path": "/",
        "CreateDate": datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
    }
    if days_since_login is not None:
        last_used = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_since_login)
        user["PasswordLastUsed"] = last_used
    return user


def _mock_iam(users, policies=None, mfa_devices=None, tags=None):
    client = MagicMock()
    client.list_users.return_value = {"Users": users}
    client.list_attached_user_policies.return_value = {"AttachedPolicies": policies or []}
    client.list_mfa_devices.return_value = {"MFADevices": mfa_devices or []}
    client.list_user_tags.return_value = {"Tags": tags or []}
    return client


def test_stale_account_flagged():
    client = _mock_iam([_make_user("alice", days_since_login=100)])
    findings = collect(iam_client=client)
    stale = [f for f in findings if f["finding_type"] == "stale_account"]
    assert len(stale) == 1
    assert stale[0]["username"] == "alice"
    assert stale[0]["severity"] == "Medium"


def test_recent_login_not_flagged():
    client = _mock_iam([_make_user("bob", days_since_login=10)])
    findings = collect(iam_client=client)
    assert not any(f["finding_type"] == "stale_account" for f in findings)


def test_admin_without_mfa_flagged():
    policies = [{"PolicyArn": ADMIN_POLICY_ARN, "PolicyName": "AdministratorAccess"}]
    client = _mock_iam([_make_user("carol", days_since_login=10)], policies=policies, mfa_devices=[])
    findings = collect(iam_client=client)
    mfa_findings = [f for f in findings if f["finding_type"] == "admin_without_mfa"]
    assert len(mfa_findings) == 1
    assert mfa_findings[0]["severity"] == "High"


def test_admin_missing_manager_tag_flagged():
    policies = [{"PolicyArn": ADMIN_POLICY_ARN, "PolicyName": "AdministratorAccess"}]
    client = _mock_iam([_make_user("dave", days_since_login=10)], policies=policies, tags=[])
    findings = collect(iam_client=client)
    assert any(f["finding_type"] == "admin_missing_manager" for f in findings)


def test_admin_with_mfa_and_manager_not_flagged():
    policies = [{"PolicyArn": ADMIN_POLICY_ARN, "PolicyName": "AdministratorAccess"}]
    mfa = [{"SerialNumber": "arn:aws:iam::123:mfa/dave", "UserName": "dave", "EnableDate": datetime.datetime.now(datetime.timezone.utc)}]
    tags = [{"Key": "Manager", "Value": "jane.doe"}]
    client = _mock_iam([_make_user("dave", days_since_login=10)], policies=policies, mfa_devices=mfa, tags=tags)
    findings = collect(iam_client=client)
    assert all(f["username"] != "dave" for f in findings)


def test_returns_empty_list_for_no_users():
    assert collect(iam_client=_mock_iam([])) == []
