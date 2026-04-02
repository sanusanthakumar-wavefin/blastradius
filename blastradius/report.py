"""Report formatter for BlastRadius — generates markdown PR comments."""

from __future__ import annotations

from dataclasses import dataclass, field


RISK_EMOJI = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🔴",
    "CRITICAL": "🚨",
    "UNKNOWN": "❓",
}

RISK_COLOR = {
    "LOW": "#22c55e",
    "MEDIUM": "#f59e0b",
    "HIGH": "#ef4444",
    "CRITICAL": "#dc2626",
    "UNKNOWN": "#94a3b8",
}


@dataclass
class DownstreamImpact:
    """A downstream service/repo impacted by this PR."""

    repo: str
    files: list[str]
    symbols_matched: list[str]
    impact_type: str  # "breaking", "version-bump", "non-breaking", "test-only"
    deploy_order: int | None = None
    blocking: bool = False
    incident_history: list[dict] = field(default_factory=list)


@dataclass
class BlastRadiusReport:
    """Complete blast radius report data."""

    pr_url: str
    pr_title: str
    risk_level: str
    risk_reason: str
    downstream_impacts: list[DownstreamImpact]
    deploy_order: list[dict]
    warnings: list[str]
    safe_to_merge: bool
    runtime_deps: list[dict] = field(default_factory=list)
    incidents: list[dict] = field(default_factory=list)
    mermaid_dag: str = ""


def format_report(report: BlastRadiusReport) -> str:
    """Generate the full markdown report for a PR comment."""
    emoji = RISK_EMOJI.get(report.risk_level, "❓")
    lines = [
        f"## {emoji} BlastRadius Report",
        "",
        f"**Risk Level: {report.risk_level}** — {report.risk_reason}",
        "",
    ]

    # Downstream impacts table
    if report.downstream_impacts:
        lines.append(f"### Downstream Services Affected ({len(report.downstream_impacts)})")
        lines.append("")
        lines.append("| Service | Files | Impact | Deploy Order |")
        lines.append("|---------|-------|--------|-------------|")
        for impact in report.downstream_impacts:
            files = ", ".join(impact.files[:3])
            if len(impact.files) > 3:
                files += f" +{len(impact.files) - 3} more"
            order = f"① Deploy first" if impact.blocking else (f"Step {impact.deploy_order}" if impact.deploy_order else "⚡ Non-blocking")
            lines.append(f"| `{impact.repo}` | {files} | {impact.impact_type} | {order} |")
        lines.append("")
    else:
        lines.append("### ✅ No downstream services affected")
        lines.append("")

    # Deploy order (if needed)
    if report.deploy_order:
        lines.append("### 📋 Required Deploy Order")
        lines.append("")
        for step in report.deploy_order:
            blocking = " ⛔ **BLOCKING**" if step.get("blocking") else ""
            lines.append(f"{step.get('step', '•')}. `{step.get('repo', '?')}` — {step.get('action', '?')}{blocking}")
        lines.append("")

    # Incident memory
    if report.incidents:
        lines.append("### ⚠️ Incident History")
        lines.append("")
        lines.append("> These services/files were involved in recent incidents:")
        lines.append("")
        for inc in report.incidents:
            ttr = f", TTR: {inc.get('ttr', '?')}" if inc.get("ttr") else ""
            lines.append(f"- **[{inc.get('severity', '?')}]** {inc.get('title', '?')} ({inc.get('date', '?')}{ttr})")
        lines.append("")

    # Mermaid DAG
    if report.mermaid_dag:
        lines.append("### 🔀 Deploy Dependency Graph")
        lines.append("")
        lines.append("```mermaid")
        lines.append(report.mermaid_dag)
        lines.append("```")
        lines.append("")

    # Warnings
    if report.warnings:
        lines.append("### ⚡ Warnings")
        lines.append("")
        for w in report.warnings:
            lines.append(f"- {w}")
        lines.append("")

    # Merge safety
    if report.safe_to_merge:
        lines.append("> ✅ **Safe to merge** without cross-team coordination.")
    else:
        lines.append("> ⛔ **Do NOT merge** without coordinating deployments with the affected services above.")

    lines.append("")
    lines.append("---")
    lines.append("*Powered by BlastRadius — GitHub Code Search + Datadog APM + AI Analysis*")

    return "\n".join(lines)


def generate_mermaid_dag(pr_repo: str, deploy_order: list[dict], downstream: list[DownstreamImpact]) -> str:
    """Generate a Mermaid diagram showing the deploy dependency graph."""
    if not deploy_order and not downstream:
        return ""

    lines = ["graph LR"]
    node_styles = {}

    # Add PR node
    pr_id = _safe_id(pr_repo)
    lines.append(f'    {pr_id}["{pr_repo}<br/>This PR"]')
    node_styles[pr_id] = RISK_COLOR["MEDIUM"]

    # Add deploy order nodes
    for step in deploy_order:
        repo = step.get("repo", "?")
        repo_id = _safe_id(repo)
        action = step.get("action", "")
        lines.append(f'    {repo_id}["{repo}<br/>{action}"]')

        if step.get("blocking"):
            lines.append(f"    {repo_id} -->|must deploy first| {pr_id}")
            node_styles[repo_id] = RISK_COLOR["HIGH"]
        else:
            lines.append(f"    {pr_id} --> {repo_id}")
            node_styles[repo_id] = RISK_COLOR["LOW"]

    # Add downstream nodes not in deploy order
    order_repos = {step.get("repo") for step in deploy_order}
    for impact in downstream:
        if impact.repo not in order_repos:
            repo_id = _safe_id(impact.repo)
            lines.append(f'    {repo_id}["{impact.repo}"]')
            lines.append(f"    {pr_id} -.-> {repo_id}")
            node_styles[repo_id] = "#94a3b8"

    # Add styles
    for node_id, color in node_styles.items():
        lines.append(f"    style {node_id} fill:{color},color:#fff")

    return "\n".join(lines)


def _safe_id(name: str) -> str:
    """Convert a repo/service name to a valid Mermaid node ID."""
    return name.replace("/", "_").replace("-", "_").replace(".", "_")
