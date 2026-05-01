import boto3
import datetime
import json
import logging
import os

from iam_findings import collect as collect_iam
from access_analyzer import collect as collect_access_analyzer
from security_hub import collect as collect_security_hub
from narrative import generate as generate_narrative
from report import render as render_report

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"
REPORT_BUCKET = os.environ.get("REPORT_BUCKET", "")


def lambda_handler(event, context, s3_client=None):
    account_id = context.invoked_function_arn.split(":")[4]
    today = datetime.date.today().strftime("%Y%m%d")

    findings = _load_demo_data() if DEMO_MODE else _collect_live_findings()
    narrative = generate_narrative(findings)
    html = render_report(findings, narrative, account_id, today)

    report_key = f"access-review-{today}.html"
    if s3_client is None:
        s3_client = boto3.client("s3")
    s3_client.put_object(Bucket=REPORT_BUCKET, Key=report_key, Body=html, ContentType="text/html")

    logger.info(json.dumps({"status": "success", "report": report_key, "account_id": account_id}))
    return {"statusCode": 200, "body": f"Report generated: s3://{REPORT_BUCKET}/{report_key}"}


def _load_demo_data():
    demo_path = os.path.join(os.path.dirname(__file__), "mock_findings.json")
    with open(demo_path) as f:
        return json.load(f)


def _collect_live_findings():
    findings = {"iam": [], "access_analyzer": [], "security_hub": []}
    for key, collector in [
        ("iam", collect_iam),
        ("access_analyzer", collect_access_analyzer),
        ("security_hub", collect_security_hub),
    ]:
        try:
            findings[key] = collector()
        except Exception as e:
            logger.error(json.dumps({"module": key, "error": str(e)}))
    return findings
