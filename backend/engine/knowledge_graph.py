"""In-memory security knowledge graph.

Nodes: skills, tools, permissions, files, network_endpoints, policies
Edges: skill→uses→tool, skill→accesses→filesystem, skill→connects_to→network
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sentinel.models.skill import SkillProfile


@dataclass
class GraphNode:
    """A node in the knowledge graph."""

    id: str
    kind: str  # skill, tool, network_endpoint, filesystem, policy
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A directed edge between two nodes."""

    source: str
    target: str
    relation: str  # uses, accesses, connects_to, governed_by


class SecurityKnowledgeGraph:
    """
    In-memory security knowledge graph backed by plain Python dicts.

    Tracks relationships between skills, tools, files, network endpoints,
    and policies discovered during scans.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        # Reverse index: node_id → list of edges where it's the source
        self._out_edges: dict[str, list[GraphEdge]] = defaultdict(list)
        # Skill name → risk_score for fast queries
        self._skill_risk: dict[str, int] = {}

    # ── Mutation ──────────────────────────────────────────────────────────

    def _add_node(self, node: GraphNode) -> None:
        self._nodes[node.id] = node

    def _add_edge(self, edge: GraphEdge) -> None:
        self._edges.append(edge)
        self._out_edges[edge.source].append(edge)

    def add_skill(
        self, profile: SkillProfile, risk_score: int = 0, risk_level: str = "Low"
    ) -> None:
        """Add a skill and its relationships to the graph."""
        skill_id = f"skill:{profile.name}"
        self._add_node(
            GraphNode(
                id=skill_id,
                kind="skill",
                attrs={
                    "name": profile.name,
                    "path": profile.path,
                    "trust_score": profile.trust_score,
                    "trust_score_value": profile.trust_score_value,
                    "shell_access": profile.shell_access,
                    "injection_risk": profile.injection_risk,
                    "credential_exposure": profile.credential_exposure,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                },
            )
        )
        self._skill_risk[profile.name] = risk_score

        # Network endpoint edges
        for domain in profile.outbound_domains:
            net_id = f"network:{domain}"
            self._add_node(GraphNode(id=net_id, kind="network_endpoint", attrs={"domain": domain}))
            self._add_edge(GraphEdge(source=skill_id, target=net_id, relation="connects_to"))

        # Tool usage edges (from shell evidence)
        for evidence in profile.shell_evidence:
            tool_id = f"tool:{evidence}"
            self._add_node(GraphNode(id=tool_id, kind="tool", attrs={"description": evidence}))
            self._add_edge(GraphEdge(source=skill_id, target=tool_id, relation="uses"))

    # ── Queries ───────────────────────────────────────────────────────────

    def get_skill_graph(self, skill_name: str) -> dict[str, Any]:
        """Return a node + its immediate edges as a JSON-serializable dict."""
        skill_id = f"skill:{skill_name}"
        node = self._nodes.get(skill_id)
        if not node:
            return {}
        edges = self._out_edges.get(skill_id, [])
        neighbors = [
            {
                "id": e.target,
                "relation": e.relation,
                "node": self._nodes.get(e.target, GraphNode(e.target, "unknown")).attrs,
            }
            for e in edges
        ]
        return {"node": node.attrs, "edges": neighbors}

    def query_skills_by_tool(self, tool_description: str) -> list[str]:
        """Return skill names that use a given tool description (substring match)."""
        results: list[str] = []
        for edge in self._edges:
            if edge.relation == "uses" and tool_description.lower() in edge.target.lower():
                skill_name = edge.source.removeprefix("skill:")
                if skill_name not in results:
                    results.append(skill_name)
        return results

    def query_skills_by_risk(self, min_score: int) -> list[str]:
        """Return skill names with risk_score >= min_score."""
        return [name for name, score in self._skill_risk.items() if score >= min_score]

    def export_graph(self) -> dict[str, Any]:
        """Export the full graph as a JSON-serializable dict."""
        return {
            "nodes": [{"id": n.id, "kind": n.kind, "attrs": n.attrs} for n in self._nodes.values()],
            "edges": [
                {"source": e.source, "target": e.target, "relation": e.relation}
                for e in self._edges
            ],
            "stats": {
                "total_nodes": len(self._nodes),
                "total_edges": len(self._edges),
                "skills": len(self._skill_risk),
            },
        }

    def clear(self) -> None:
        """Reset the graph (called before each new scan)."""
        self._nodes.clear()
        self._edges.clear()
        self._out_edges.clear()
        self._skill_risk.clear()


# Module-level singleton
knowledge_graph = SecurityKnowledgeGraph()
