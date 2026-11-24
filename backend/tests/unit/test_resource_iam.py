"""Resource-level access collectors: S3 / KMS policies, GCP resource IAM, Cloud Identity groups. Only read calls are made;
a refused call is reported as missing permission and marks the result incomplete (nothing gets marked removed)."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from app.services.access.resource_iam import AwsResourcePolicies, GcpGroupMembers, GcpResourceIam
from app.services.vuln.common import HttpError


def _err(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


class Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return iter(self.pages)


class S3:
    calls: list = []

    def list_buckets(self):
        return {"Buckets": [{"Name": "data"}, {"Name": "plain"}]}

    def get_bucket_policy(self, Bucket):
        if Bucket == "plain":
            raise _err("NoSuchBucketPolicy")
        return {"Policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::222:role/partner", "arn:aws:iam::111:user/dev"]}, "Action": "s3:GetObject"},
            {"Effect": "Deny", "Principal": "*", "Action": "s3:*"},
            {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]})}


class Kms:
    def __init__(self, deny=False):
        self.deny = deny

    def get_paginator(self, _):
        if self.deny:
            raise _err("AccessDeniedException")
        return Pager([{"Keys": [{"KeyId": "k1", "KeyArn": "arn:aws:kms:eu-west-1:111:key/k1"}, {"KeyId": "k2", "KeyArn": "arn:aws:kms:eu-west-1:111:key/k2"}]}])

    def describe_key(self, KeyId):
        return {"KeyMetadata": {"KeyManager": "CUSTOMER" if KeyId == "k1" else "AWS", "KeyState": "Enabled", "Description": "app key"}}

    def get_key_policy(self, KeyId, PolicyName):
        return {"Policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111:root"}, "Action": "kms:*"}]})}


class Conn:
    def __init__(self, kms_deny=False):
        self.kms_deny = kms_deny

    def session_for(self, *_):
        return object()

    def regions(self, _):
        return ["eu-west-1"]

    def client(self, _s, service, region=None):
        return S3() if service == "s3" else Kms(self.kms_deny)


def test_aws_bucket_and_key_policies():
    res = AwsResourcePolicies(Conn()).collect("111")
    assert res.complete
    by = {(f.resource_name, f.principal_id): f for f in res.assignments}
    partner = by[("data", "arn:aws:iam::222:role/partner")]
    assert partner.principal_type == "Role" and partner.inherited_from == "cross-account" and partner.scope_level == "resource"
    assert by[("data", "arn:aws:iam::111:user/dev")].inherited_from is None
    assert by[("data", "*")].principal_type == "Anyone" and by[("data", "*")].condition  # public-with-condition statement kept, deny ignored
    assert ("app key", "arn:aws:iam::111:root") in by and not any(f.resource_name == "plain" for f in res.assignments)
    assert len([f for f in res.assignments if f.scope_path.startswith("arn:aws:kms")]) == 1  # AWS-managed key skipped


def test_aws_kms_denied_is_reported_not_empty():
    res = AwsResourcePolicies(Conn(kms_deny=True)).collect("111")
    assert not res.complete
    kms = next(c for c in res.coverage if c["source"] == "aws_resource_policy:kms")
    assert kms["state"] == "ACCESS_DENIED"
    assert any(c["source"] == "aws_resource_policy:s3" and c["state"] == "OK" for c in res.coverage)


def test_gcp_resource_iam_pages_and_skips_project_policy():
    pages = {None: {"results": [
        {"resource": "//cloudresourcemanager.googleapis.com/projects/123", "policy": {"bindings": [{"role": "roles/owner", "members": ["user:a@x.com"]}]}},
        {"resource": "//storage.googleapis.com/projects/_/buckets/raw", "policy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["group:eng@x.com"]}]}}],
        "nextPageToken": "t2"},
        "t2": {"results": [{"resource": "//bigquery.googleapis.com/projects/p/datasets/d", "policy": {"bindings": [
            {"role": "roles/bigquery.dataViewer", "members": ["serviceAccount:etl@p.iam.gserviceaccount.com"], "condition": {"expression": "request.time < x"}}]}}]}}
    res = GcpResourceIam(lambda url, params: pages[params.get("pageToken")]).collect("p")
    assert res.complete and len(res.assignments) == 2
    assert {f.resource_name for f in res.assignments} == {"raw", "d"} and res.assignments[1].condition == "request.time < x"


def test_gcp_resource_iam_permission_denied():
    def get(url, params):
        raise HttpError(403, "cloudasset.assets.searchAllIamPolicies denied")
    res = GcpResourceIam(get).collect("p")
    assert not res.complete and res.coverage[0]["state"] == "ACCESS_DENIED" and res.assignments == []


def test_gcp_group_members_transitive_and_failure_keeps_incomplete():
    def get(url, params):
        if url.endswith("groups:lookup"):
            if params["groupKey.id"] == "secret@x.com":
                raise HttpError(403, "denied")
            return {"name": "groups/abc"}
        return {"memberships": [{"preferredMemberKey": [{"id": "ana@x.com"}]}, {"preferredMemberKey": [{"id": "etl@p.iam.gserviceaccount.com"}]}]}
    ok = GcpGroupMembers(get, "1").collect({"group:eng@x.com"})
    assert ok.members_complete and {m.member_id for m in ok.members} == {"user:ana@x.com", "serviceAccount:etl@p.iam.gserviceaccount.com"}
    bad = GcpGroupMembers(get, "1").collect({"group:eng@x.com", "group:secret@x.com"})
    assert not bad.members_complete and any(c["state"] == "ACCESS_DENIED" for c in bad.coverage)
