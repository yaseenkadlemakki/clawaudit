"""Tests for the in-memory knowledge graph."""

from __future__ import annotations

from unittest.mock import MagicMock

from backend.engine.knowledge_graph import SecurityKnowledgeGraph


def make_profile(name="test-skill", domains=None, shell_evidence=None, **kwargs):
    p = MagicMock()
    p.name = name
    p.path = f"/skills/{name}/SKILL.md"
    p.trust_score = "CAUTION"
    p.trust_score_value = 60
    p.shell_access = bool(shell_evidence)
    p.outbound_domains = domains or []
    p.injection_risk = kwargs.get("injection_risk", "LOW")
    p.credential_exposure = False
    p.shell_evidence = shell_evidence or []
    return p


def test_add_skill_creates_node():
    g = SecurityKnowledgeGraph()
    p = make_profile("my-skill")
    g.add_skill(p, risk_score=10, risk_level="Low")
    result = g.get_skill_graph("my-skill")
    assert result["node"]["name"] == "my-skill"
    assert result["node"]["risk_score"] == 10


def test_network_edges_created():
    g = SecurityKnowledgeGraph()
    p = make_profile("net-skill", domains=["api.github.com"])
    g.add_skill(p, risk_score=15, risk_level="Low")
    result = g.get_skill_graph("net-skill")
    relations = [e["relation"] for e in result["edges"]]
    assert "connects_to" in relations


def test_tool_edges_created():
    g = SecurityKnowledgeGraph()
    p = make_profile("shell-skill", shell_evidence=["bash reference"])
    g.add_skill(p, risk_score=30, risk_level="Medium")
    result = g.get_skill_graph("shell-skill")
    relations = [e["relation"] for e in result["edges"]]
    assert "uses" in relations


def test_query_skills_by_risk():
    g = SecurityKnowledgeGraph()
    g.add_skill(make_profile("low-risk"), risk_score=10, risk_level="Low")
    g.add_skill(make_profile("high-risk"), risk_score=80, risk_level="Critical")
    result = g.query_skills_by_risk(min_score=70)
    assert "high-risk" in result
    assert "low-risk" not in result


def test_query_skills_by_tool():
    g = SecurityKnowledgeGraph()
    p = make_profile("bash-user", shell_evidence=["bash reference"])
    g.add_skill(p, risk_score=30, risk_level="Medium")
    result = g.query_skills_by_tool("bash")
    assert "bash-user" in result


def test_export_graph_serializable():
    g = SecurityKnowledgeGraph()
    import json

    g.add_skill(make_profile("skill-a", domains=["a.com"]), risk_score=5, risk_level="Low")
    export = g.export_graph()
    json.dumps(export)  # should not raise
    assert export["stats"]["skills"] == 1


def test_get_unknown_skill_returns_empty():
    g = SecurityKnowledgeGraph()
    assert g.get_skill_graph("nonexistent") == {}


def test_clear_resets_graph():
    g = SecurityKnowledgeGraph()
    g.add_skill(make_profile("to-clear"), risk_score=0, risk_level="Low")
    g.clear()
    assert g.export_graph()["stats"]["total_nodes"] == 0
