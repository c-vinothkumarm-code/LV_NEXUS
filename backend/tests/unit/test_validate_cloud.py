from app.services.connector import CheckResult, DiscoveredScope


class FakeConn:
    provider = "aws"

    def missing_configuration(self):
        return []

    def discover(self):
        return [DiscoveredScope(provider="aws", external_id="111111111111", name="prod", provider_state="ACTIVE", is_active=True),
                DiscoveredScope(provider="aws", external_id="222222222222", name="closed", provider_state="SUSPENDED", is_active=False)]

    def validate(self, scope):
        return {"authentication": CheckResult("pass", "Role assumed"),
                "billing": CheckResult("fail", "ce:GetCostAndUsage denied", "Grant ce:GetCostAndUsage to CloudNexusManagementReader")}


def test_validate_cloud_reports_each_check_and_fix(monkeypatch, tmp_path, capsys):
    import app.validate_cloud as v
    from app.core.config import Settings
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(v, "get_settings", lambda: Settings(_env_file=None, aws_enabled=True, aws_member_role_name="CloudNexusReadOnly"))
    monkeypatch.setattr("app.services.registry.build_connectors", lambda s: [FakeConn()])
    assert v.main(["aws"]) == 1  # a FAIL makes the exit code non-zero
    out = capsys.readouterr().out
    assert "Discovery OK: 2 found, 1 active" in out and "FAIL  billing" in out and "fix: Grant ce:GetCostAndUsage" in out and "closed" not in out
    report = next(tmp_path.glob("validation-aws-*.md")).read_text(encoding="utf-8")
    assert "| prod | billing | FAIL |" in report


def test_validate_cloud_refuses_when_disabled(monkeypatch, capsys):
    import app.validate_cloud as v
    from app.core.config import Settings
    monkeypatch.setattr(v, "get_settings", lambda: Settings(_env_file=None, gcp_enabled=False))
    assert v.main(["gcp"]) == 2 and "GCP_ENABLED is false" in capsys.readouterr().out
