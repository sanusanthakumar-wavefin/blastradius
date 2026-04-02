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
    vulnerabilities: list[dict] = field(default_factory=list)
    repo_incidents: list[dict] = field(default_factory=list)
    package_changes: list[dict] = field(default_factory=list)
    service_consumers: list[dict] = field(default_factory=list)
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
    code_impacts = [i for i in report.downstream_impacts if i.impact_type != "shared-dependency"]
    pkg_impacts = [i for i in report.downstream_impacts if i.impact_type == "shared-dependency"]

    if code_impacts:
        lines.append(f"### Downstream Services Affected ({len(code_impacts)})")
        lines.append("")
        lines.append("| Service | Files | Impact | Deploy Order |")
        lines.append("|---------|-------|--------|-------------|")
        for impact in code_impacts:
            files = ", ".join(impact.files[:3])
            if len(impact.files) > 3:
                files += f" +{len(impact.files) - 3} more"
            order = f"① Deploy first" if impact.blocking else (f"Step {impact.deploy_order}" if impact.deploy_order else "⚡ Non-blocking")
            lines.append(f"| `{impact.repo}` | {files} | {impact.impact_type} | {order} |")
        lines.append("")
    elif not pkg_impacts:
        lines.append("### ✅ No downstream services affected")
        lines.append("")

    # Shared dependency services
    if pkg_impacts:
        # Group by package
        pkg_repos: dict[str, list[DownstreamImpact]] = {}
        for impact in pkg_impacts:
            for sym in impact.symbols_matched:
                pkg_repos.setdefault(sym, []).append(impact)

        lines.append(f"### 🔗 Services Sharing Changed Dependencies ({len(pkg_impacts)} repos)")
        lines.append("")
        lines.append("> These services also use the same packages being changed in this PR and may need similar upgrades.")
        lines.append("")
        for pkg_name, impacts in pkg_repos.items():
            lines.append(f"**`{pkg_name}`** — used by {len(impacts)} other services:")
            lines.append("")
            lines.append("| Service | Dependency File |")
            lines.append("|---------|----------------|")
            for impact in impacts:
                repo_short = impact.repo.split("/")[-1] if "/" in impact.repo else impact.repo
                dep_file = impact.files[0] if impact.files else "—"
                lines.append(f"| `{repo_short}` | {dep_file} |")
            lines.append("")

    # Service consumers — services that depend on this service
    if report.service_consumers:
        # Group by dependency type
        by_type: dict[str, list[dict]] = {}
        for sc in report.service_consumers:
            dep_type = sc.get("type", "reference")
            by_type.setdefault(dep_type, []).append(sc)

        lines.append(f"### 🏗️ Services Depending on This Service ({len(report.service_consumers)} refs)")
        lines.append("")
        lines.append("> Changes to this service may impact these consumers:")
        lines.append("")
        lines.append("| Service | Type | File |")
        lines.append("|---------|------|------|")
        for sc in report.service_consumers:
            repo_short = sc.get("repo", "?").split("/")[-1]
            lines.append(f"| `{repo_short}` | {sc.get('type', '?')} | {sc.get('file', '—')} |")
        lines.append("")

    # Deploy order (if needed)
    if report.deploy_order:
        lines.append("### 📋 Required Deploy Order")
        lines.append("")
        for step in report.deploy_order:
            blocking = " ⛔ **BLOCKING**" if step.get("blocking") else ""
            lines.append(f"{step.get('step', '•')}. `{step.get('repo', '?')}` — {step.get('action', '?')}{blocking}")
        lines.append("")

    # Incident memory (from Datadog)
    if report.incidents:
        lines.append("### ⚠️ Incident History (Datadog)")
        lines.append("")
        lines.append("> These services/files were involved in recent incidents:")
        lines.append("")
        for inc in report.incidents:
            ttr = f", TTR: {inc.get('ttr', '?')}" if inc.get("ttr") else ""
            lines.append(f"- **[{inc.get('severity', '?')}]** {inc.get('title', '?')} ({inc.get('date', '?')}{ttr})")
        lines.append("")

    # Package changes section
    if report.package_changes:
        lines.append(f"### 📦 Package Changes in This PR ({len(report.package_changes)})")
        lines.append("")
        lines.append("| Package | Change | Version |")
        lines.append("|---------|--------|---------|")
        for pc in report.package_changes:
            icon = {"added": "➕", "removed": "➖", "updated": "🔄"}.get(pc.get("change_type", ""), "•")
            if pc.get("change_type") == "updated":
                ver = f"`{pc.get('old_version', '?')}` → `{pc.get('new_version', '?')}`"
            elif pc.get("change_type") == "added":
                ver = f"`{pc.get('new_version', '?')}`" if pc.get("new_version") else "—"
            else:
                ver = f"`{pc.get('old_version', '?')}`" if pc.get("old_version") else "—"
            lines.append(f"| `{pc.get('name', '?')}` | {icon} {pc.get('change_type', '?')} | {ver} |")
        lines.append("")

    # Vulnerability alerts
    if report.vulnerabilities:
        resolved = [v for v in report.vulnerabilities if v.get("pr_impact") == "potentially_resolved"]
        existing = [v for v in report.vulnerabilities if v.get("pr_impact") != "potentially_resolved"]
        critical = [v for v in report.vulnerabilities if v.get("severity") == "critical"]
        high = [v for v in report.vulnerabilities if v.get("severity") == "high"]

        lines.append(f"### 🛡️ Vulnerability Scan ({len(report.vulnerabilities)} open alerts)")
        lines.append("")

        if resolved:
            lines.append(f"#### ✅ Potentially Resolved by This PR ({len(resolved)})")
            lines.append("")
            lines.append("> These vulnerabilities may be fixed by the package updates in this PR.")
            lines.append("")
            lines.append("| Package | Severity | Summary | Fixed In |")
            lines.append("|---------|----------|---------|----------|")
            for vuln in sorted(resolved, key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(v.get("severity", ""), 4)):
                sev_emoji = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}.get(vuln.get("severity", ""), "❓")
                summary = vuln.get("summary", "")[:80]
                patched = f"`{vuln.get('patched_version')}`" if vuln.get("patched_version") else "—"
                lines.append(f"| `{vuln.get('package', '?')}` | {sev_emoji} {vuln.get('severity', '?')} | {summary} | {patched} |")
            lines.append("")

        if existing:
            label = "Remaining" if resolved else "Existing"
            lines.append(f"#### ⚠️ {label} Vulnerabilities ({len(existing)})")
            lines.append("")
            if critical or high:
                lines.append("> ⚠️ **Unpatched security vulnerabilities in this repo!**")
                lines.append("")
            lines.append("| Package | Severity | Summary |")
            lines.append("|---------|----------|---------|")
            for vuln in sorted(existing, key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(v.get("severity", ""), 4)):
                sev_emoji = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}.get(vuln.get("severity", ""), "❓")
                summary = vuln.get("summary", "")[:80]
                lines.append(f"| `{vuln.get('package', '?')}` | {sev_emoji} {vuln.get('severity', '?')} | {summary} |")
            lines.append("")

        if critical:
            lines.append(f"> 🚨 **{len(critical)} CRITICAL** vulnerabilities — coordinate patching!")
            lines.append("")

    # Recent incidents from GitHub issues
    if report.repo_incidents:
        lines.append(f"### 🔥 Recent Incidents ({len(report.repo_incidents)} found)")
        lines.append("")
        lines.append("> Recent incidents/hotfixes in this repo:")
        lines.append("")
        lines.append("| Issue | Status | Date | Labels |")
        lines.append("|-------|--------|------|--------|")
        for inc in report.repo_incidents:
            state_icon = "✅" if inc.get("state") == "closed" else "🔴"
            labels = ", ".join(f"`{l}`" for l in inc.get("labels", [])[:3])
            title = inc.get("title", "?")[:60]
            lines.append(f"| [{title}]({inc.get('url', '')}) | {state_icon} {inc.get('state', '?')} | {inc.get('date', '?')} | {labels} |")
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


def generate_mermaid_dag(
    pr_repo: str,
    deploy_order: list[dict],
    downstream: list[DownstreamImpact],
    package_changes: list[dict] | None = None,
    vulnerabilities: list[dict] | None = None,
    repo_incidents: list[dict] | None = None,
    service_consumers: list[dict] | None = None,
) -> str:
    """Generate a Mermaid diagram showing the deploy/dependency graph."""
    package_changes = package_changes or []
    vulnerabilities = vulnerabilities or []
    repo_incidents = repo_incidents or []
    service_consumers = service_consumers or []

    has_downstream = bool(deploy_order or downstream)
    has_packages = bool(package_changes)
    has_vulns = bool(vulnerabilities)
    has_incidents = bool(repo_incidents)
    has_consumers = bool(service_consumers)

    if not has_downstream and not has_packages and not has_consumers:
        return ""

    lines = ["graph LR"]
    node_styles = {}

    # Add PR node
    pr_id = _safe_id(pr_repo)
    lines.append(f'    {pr_id}["{pr_repo}<br/>This PR"]')
    node_styles[pr_id] = RISK_COLOR["MEDIUM"]

    # --- Downstream service nodes ---
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

    # Add code-impact downstream nodes not in deploy order
    order_repos = {step.get("repo") for step in deploy_order}
    for impact in downstream:
        if impact.repo not in order_repos and impact.impact_type != "shared-dependency":
            repo_id = _safe_id(impact.repo)
            lines.append(f'    {repo_id}["{impact.repo}"]')
            lines.append(f"    {pr_id} -.-> {repo_id}")
            node_styles[repo_id] = "#94a3b8"

    # Collect shared-dependency repos grouped by package for linking later
    shared_dep_by_pkg: dict[str, list[str]] = {}
    for impact in downstream:
        if impact.impact_type == "shared-dependency":
            for sym in impact.symbols_matched:
                shared_dep_by_pkg.setdefault(sym, []).append(impact.repo)

    # --- Package dependency nodes ---
    if has_packages:
        for pc in package_changes:
            pkg_name = pc.get("name", "?")
            pkg_id = _safe_id(f"pkg_{pkg_name}")
            change = pc.get("change_type", "?")
            icon = {"added": "+", "removed": "-", "updated": "↑"}.get(change, "•")
            if change == "updated":
                ver = f"{pc.get('old_version', '?')} → {pc.get('new_version', '?')}"
            elif change == "added":
                ver = pc.get("new_version", "new")
            else:
                ver = pc.get("old_version", "removed")
            lines.append(f'    {pkg_id}(["{icon} {pkg_name}<br/>{ver}"])')
            lines.append(f"    {pr_id} --> {pkg_id}")

            color = {"added": "#22c55e", "removed": "#ef4444", "updated": "#3b82f6"}.get(change, "#94a3b8")
            node_styles[pkg_id] = color

            # Link shared-dependency repos to this package node
            import re as _re
            pkg_normalized = _re.sub(r"[-_.]+", "-", pkg_name).lower()
            for dep_pkg, dep_repos in shared_dep_by_pkg.items():
                if _re.sub(r"[-_.]+", "-", dep_pkg).lower() == pkg_normalized:
                    # Cap at 5 repos to keep the chart readable
                    for repo_name in dep_repos[:5]:
                        short = repo_name.split("/")[-1] if "/" in repo_name else repo_name
                        dep_repo_id = _safe_id(f"dep_{short}")
                        if dep_repo_id not in node_styles:
                            lines.append(f'    {dep_repo_id}["{short}"]')
                            lines.append(f"    {pkg_id} -.->|also uses| {dep_repo_id}")
                            node_styles[dep_repo_id] = "#94a3b8"
                    if len(dep_repos) > 5:
                        more_id = _safe_id(f"more_{pkg_name}")
                        lines.append(f'    {more_id}["+{len(dep_repos) - 5} more"]')
                        lines.append(f"    {pkg_id} -.-> {more_id}")
                        node_styles[more_id] = "#94a3b8"

            # Link resolved vulns to their package
            for vuln in vulnerabilities:
                if vuln.get("pr_impact") == "potentially_resolved":
                    vuln_pkg = vuln.get("package", "")
                    if _re.sub(r"[-_.]+", "-", vuln_pkg).lower() == _re.sub(r"[-_.]+", "-", pkg_name).lower():
                        vuln_id = _safe_id(f"vuln_{vuln_pkg}_{vuln.get('severity', '')}")
                        if vuln_id not in node_styles:
                            sev = vuln.get("severity", "?")
                            lines.append(f'    {vuln_id}{{"🛡️ {sev}: {vuln_pkg}"}}')
                            lines.append(f"    {pkg_id} -->|resolves| {vuln_id}")
                            node_styles[vuln_id] = "#22c55e"

        # Show unresolved vulns connected to PR
        unresolved_critical = [v for v in vulnerabilities if v.get("pr_impact") != "potentially_resolved" and v.get("severity") in ("critical", "high")]
        if unresolved_critical:
            vuln_group_id = _safe_id("vuln_unresolved")
            count = len(unresolved_critical)
            sev_counts = {}
            for v in unresolved_critical:
                s = v.get("severity", "?")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            label_parts = [f"{c} {s}" for s, c in sorted(sev_counts.items())]
            lines.append(f'    {vuln_group_id}{{"⚠️ {count} open vulns<br/>{", ".join(label_parts)}"}}')
            lines.append(f"    {pr_id} -.->|existing| {vuln_group_id}")
            node_styles[vuln_group_id] = "#ef4444"

        # Show related incidents connected to PR
        if has_incidents:
            inc_id = _safe_id("incidents")
            revert_count = sum(1 for i in repo_incidents if "revert" in i.get("labels", []))
            other_count = len(repo_incidents) - revert_count
            parts = []
            if revert_count:
                parts.append(f"{revert_count} reverts")
            if other_count:
                parts.append(f"{other_count} issues")
            lines.append(f'    {inc_id}{{"🔥 {", ".join(parts)}"}}')
            lines.append(f"    {pr_id} -.->|history| {inc_id}")
            node_styles[inc_id] = "#f59e0b"

    # --- Service consumer nodes ---
    if has_consumers:
        # Deduplicate by repo
        consumer_repos: dict[str, list[str]] = {}
        for sc in service_consumers:
            repo = sc.get("repo", "?")
            short = repo.split("/")[-1] if "/" in repo else repo
            dep_type = sc.get("type", "reference")
            consumer_repos.setdefault(short, []).append(dep_type)

        shown = 0
        for short_name, types in consumer_repos.items():
            if shown >= 8:
                remaining = len(consumer_repos) - shown
                more_id = _safe_id("more_consumers")
                lines.append(f'    {more_id}["+{remaining} more services"]')
                lines.append(f"    {more_id} -->|depends on| {pr_id}")
                node_styles[more_id] = "#94a3b8"
                break
            consumer_id = _safe_id(f"svc_{short_name}")
            dep_label = types[0] if len(types) == 1 else f"{len(types)} refs"
            lines.append(f'    {consumer_id}["{short_name}"]')
            lines.append(f"    {consumer_id} -->|{dep_label}| {pr_id}")
            node_styles[consumer_id] = "#8b5cf6"
            shown += 1

    # Add styles
    for node_id, color in node_styles.items():
        lines.append(f"    style {node_id} fill:{color},color:#fff")

    return "\n".join(lines)


def _safe_id(name: str) -> str:
    """Convert a repo/service name to a valid Mermaid node ID."""
    return name.replace("/", "_").replace("-", "_").replace(".", "_")
