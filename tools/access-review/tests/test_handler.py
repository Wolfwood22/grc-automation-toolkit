import os
os.environ["DEMO_MODE"] = "true"
os.environ["REPORT_BUCKET"] = "test-bucket"

from unittest.mock import MagicMock
from handler import lambda_handler


class MockContext:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:access-review"


def test_demo_mode_returns_200():
    mock_s3 = MagicMock()
    result = lambda_handler({}, MockContext(), s3_client=mock_s3)
    assert result["statusCode"] == 200


def test_demo_mode_uploads_html_to_s3():
    mock_s3 = MagicMock()
    lambda_handler({}, MockContext(), s3_client=mock_s3)
    mock_s3.put_object.assert_called_once()
    kwargs = mock_s3.put_object.call_args[1]
    assert kwargs["Bucket"] == "test-bucket"
    assert kwargs["ContentType"] == "text/html"


def test_demo_mode_html_is_valid():
    mock_s3 = MagicMock()
    lambda_handler({}, MockContext(), s3_client=mock_s3)
    html = mock_s3.put_object.call_args[1]["Body"]
    assert "<!DOCTYPE html>" in html
    assert "Access Review" in html