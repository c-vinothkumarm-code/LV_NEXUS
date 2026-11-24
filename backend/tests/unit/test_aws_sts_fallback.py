"""RegionDisabledException on the regional STS endpoint falls back to us-east-1; other errors are not retried."""
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from app.services.aws.connector import AwsConnector


def _err(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "AssumeRole")


def _conn(region="ap-south-1"):
    c = AwsConnector.__new__(AwsConnector)
    c.settings = SimpleNamespace(aws_default_region=region)
    return c


def test_region_disabled_retries_on_us_east_1():
    calls = []

    class Sts:
        def __init__(self, region):
            self.region = region

        def assume_role(self, **kw):
            calls.append(self.region)
            if self.region != "us-east-1":
                raise _err("RegionDisabledException")
            return {"ok": True}

    c = _conn()
    c._client = lambda session, service, region=None: Sts(region or "ap-south-1")
    assert c._sts_call(None, "assume_role", RoleArn="x") == {"ok": True}
    assert calls == ["ap-south-1", "us-east-1"]


def test_access_denied_is_not_retried():
    calls = []

    class Sts:
        def assume_role(self, **kw):
            calls.append(1)
            raise _err("AccessDenied")

    c = _conn()
    c._client = lambda session, service, region=None: Sts()
    with pytest.raises(ClientError):
        c._sts_call(None, "assume_role", RoleArn="x")
    assert calls == [1]


def test_security_hub_not_enabled_is_not_a_credential_failure():
    from app.services.reliability import ProviderGuard, classify
    exc = ClientError({"Error": {"Code": "InvalidAccessException", "Message": "Account is not subscribed to AWS Security Hub CSPM"},
                       "ResponseMetadata": {"HTTPStatusCode": 401}}, "DescribeHub")
    kind, _ = classify(exc)
    assert kind == "not_enabled"
    g = ProviderGuard("aws")
    g.failure(kind, "x")
    assert not g.is_open  # other accounts keep being read
    expired = ClientError({"Error": {"Code": "ExpiredToken", "Message": "The security token included in the request is expired"},
                           "ResponseMetadata": {"HTTPStatusCode": 403}}, "DescribeHub")
    assert classify(expired)[0] == "auth_expired"
