# AWS Automated Access Review

Serverless access review system that orchestrates IAM, IAM Access Analyzer, and Security Hub
findings into an AI-narrated HTML compliance report. Deployed via CloudFormation with a weekly
EventBridge trigger.

## Architecture

```
EventBridge (weekly) → Lambda handler.py
  → iam_findings.py        Stale accounts, admin MFA, manager tags
  → access_analyzer.py     External resource exposure
  → security_hub.py        Active IAM control failures (IAM.1–IAM.9)
  → narrative.py           Mock Bedrock executive summary
  → report.py              Self-contained HTML report
  → S3                     Dated report: access-review-YYYYMMDD.html
```

## Demo Mode

Set `DEMO_MODE=true` (default) to load `mock_findings.json` instead of calling AWS APIs.
The full pipeline runs — report is generated and uploaded to S3 without requiring live IAM data.

## Deploy

```bash
# Create deployment bucket (one-time)
aws s3 mb s3://access-review-deploy-$(aws sts get-caller-identity --query Account --output text)

# Package and upload Lambda
cd lambda && zip ../lambda.zip handler.py access_analyzer.py narrative.py iam_findings.py security_hub.py mock_findings.json report.py && cd ..
aws s3 cp lambda.zip s3://access-review-deploy-ACCOUNT_ID/lambda.zip

# Deploy CloudFormation stack
aws cloudformation deploy \
  --template-file cloudformation/template.yaml \
  --stack-name access-review \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides DemoMode=true
```

## Test

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Compliance Frameworks

SOC 2 · ISO 27001 · NIST 800-53 · PCI-DSS 4.0 · CMMC Level 2 & 3
