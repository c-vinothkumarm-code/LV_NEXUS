"""LV NEXUS assistant: the management questions route to the right data tools, answers come only from stored data with
their source, follow-ups reuse context, roles only see what they may, and an AI model's text is labelled as insight."""
from __future__ import annotations

import pytest

from tests.integration.sample_estate import seed
from tests.integration.test_identity_governance import login

H = {"X-Requested-With": "mcp-dashboard"}


def ask(client, q, **kw):
    r = client.post("/api/v1/ai/ask", json={"question": q, **kw}, headers=H)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture()
def admin(client, db):
    seed(db)
    db.commit()
    login(client, db, "admin@latentview.com", "admin")
    return client


@pytest.mark.parametrize("question,tool", [
    ("Give me the current executive overview.", "executive_overview"),
    ("What are the top operational risks?", "security_risks"),
    ("Show me the critical issues requiring management attention.", "pending_actions"),
    ("Summarize the latest API failures.", "collection_health"),
    ("What are the key trends this month?", "trends"),
    ("Which actions are pending?", "pending_actions"),
    ("Generate an executive summary for the management review.", "executive_summary"),
    ("Any unusual sign-in activity?", "unusual_activity"),
    ("How do I see who has access to a resource group?", "app_help"),
])
def test_management_questions_route_to_data(admin, question, tool):
    out = ask(admin, question)
    assert tool in [r["tool"] for r in out["results"]]
    assert out["answer_source"] == "template" and out["ai_insight"] is None  # no AI model configured: factual summary only
    assert all(r["source"] for r in out["results"]) and out["suggestions"]


def test_executive_overview_uses_real_numbers(admin):
    out = ask(admin, "Give me the current executive overview.")
    facts = " ".join(x["fact"] for r in out["results"] for x in r["facts"])
    assert "Azure: 2 account(s)" in facts and "AWS: 2 account(s)" in facts and "Google Cloud: 1 account(s)" in facts
    assert "Open security findings: 2 critical, 2 high" in facts  # matches the sample estate exactly, nothing invented


def test_api_failures_name_the_failing_workflow_and_fix(admin):
    out = ask(admin, "Summarize the latest API failures.")
    facts = " ".join(x["fact"] for r in out["results"] for x in r["facts"])
    assert "cost_detail_refresh: failed" in facts and "Fix:" in facts


def test_follow_up_reuses_context_with_new_filter(admin):
    ask(admin, "What are the top operational risks?")
    out = ask(admin, "and for AWS only?")
    assert out["follow_up_of"] == "What are the top operational risks?" and out["filters"].get("provider") == "aws"
    facts = [x["fact"] for r in out["results"] if r["tool"] == "security_risks" for x in r["facts"]]
    assert facts and all("AWS" in f for f in facts)


def test_role_only_sees_permitted_data(client, db):
    seed(db)
    db.commit()
    login(client, db, "fin@latentview.com", "finops_analyst")
    out = ask(client, "What are the top operational risks?")
    assert "Top Critical / High security risks" in out["denied"] and not any(r["tool"] == "security_risks" for r in out["results"])
    pend = ask(client, "Which actions are pending?")
    text = " ".join(x["fact"] for r in pend["results"] for x in r["facts"])
    assert "Security:" not in text and "Budget:" in text and "security" in pend["results"][0]["gap"]


def test_model_text_is_labelled_insight_and_facts_still_returned(admin, monkeypatch):
    class Fake:
        model = "test-model"

        def generate(self, system, prompt):
            assert "Never invent numbers" in system and "Azure" in prompt
            return "Key points: Azure carries most of the cost (source: overview)."
    monkeypatch.setattr("app.services.ai.provider.build_provider", lambda s: Fake())
    out = ask(admin, "Give me the current executive overview.")
    assert out["answer_source"] == "model" and out["ai_insight"].startswith("Key points") and out["model"] == "test-model"
    assert "Executive overview" in out["summary"]  # the verified data is always returned next to the AI text


def test_failing_tool_reports_gap_not_crash(admin, monkeypatch):
    def boom(db, f):
        raise RuntimeError("database busy")
    import app.services.intelligence.engine as E
    for t in E.TOOLS:
        if t.name == "trends":
            monkeypatch.setattr(t, "fn", boom)
    out = ask(admin, "What are the key trends this month?")
    r = next(r for r in out["results"] if r["tool"] == "trends")
    assert r["facts"] == [] and "could not be read" in r["gap"]
