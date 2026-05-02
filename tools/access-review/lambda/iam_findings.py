import boto3
import datetime

STALE_DAYS = 90
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def collect(iam_client=None):
    if iam_client is None:
        iam_client = boto3.client("iam")

    findings = []
    today = datetime.date.today()

    for user in iam_client.list_users()["Users"]:
        username = user["UserName"]
        last_used = user.get("PasswordLastUsed")

        if last_used:
            days_since = (today - last_used.date()).days
            if days_since > STALE_DAYS:
                findings.append({
                    "username": username,
                    "finding_type": "stale_account",
                    "severity": "Medium",
                    "detail": f"No login in {days_since} days",
                })

        attached = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        is_admin = any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in attached)

        if is_admin:
            mfa = iam_client.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa:
                findings.append({
                    "username": username,
                    "finding_type": "admin_without_mfa",
                    "severity": "High",
                    "detail": "Admin user has no MFA device registered",
                })

            tags = iam_client.list_user_tags(UserName=username)["Tags"]
            if not any(t["Key"] == "Manager" for t in tags):
                findings.append({
                    "username": username,
                    "finding_type": "admin_missing_manager",
                    "severity": "Medium",
                    "detail": "Admin user has no Manager tag assigned",
                })

    return findings
