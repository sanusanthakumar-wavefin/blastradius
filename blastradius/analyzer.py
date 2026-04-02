"""Core analyzer — orchestrates GitHub, Datadog, and AI to produce a BlastRadius report."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict

from .ai_analyzer import AIAnalyzer
from .datadog_client import DatadogClient
from .github_client import GitHubClient
from .report import (
    BlastRadiusReport,
    DownstreamImpact,
    format_report,
    generate_mermaid_dag,
)

logger = logging.getLogger(__name__)


class BlastRadiusAnalyzer:
    """Main orchestrator: reads PR → finds downstream impact → AI risk analysis → report."""

    def __init__(
        self,
        github_token: str,
        openai_api_key: str | None = None,
        org: str = "waveaccounting",
        dd_api_key: str | None = None,
        dd_app_key: str | None = None,
        dd_site: str = "datadoghq.com",
        ai_model: str = "gpt-4o-mini",
    ):
        self.github = GitHubClient(token=github_token, org=org)
        self.ai = AIAnalyzer(api_key=openai_api_key, model=ai_model) if openai_api_key else None
        self.datadog = (
            DatadogClient(api_key=dd_api_key, app_key=dd_app_key, site=dd_site)
            if dd_api_key and dd_app_key
            else None
        )
        self.org = org

    def analyze_pr(self, owner: str, repo: str, pr_number: int) -> str:
        """Full blast radius analysis. Returns formatted markdown report."""
        logger.info("Analyzing PR %s/%s#%d", owner, repo, pr_number)

        # Step 1: Read the PR diff
        pr_diff = self.github.get_pr_diff(owner, repo, pr_number)
        logger.info(
            "PR '%s' has %d changed files, %d symbols detected",
            pr_diff.title,
            len(pr_diff.changed_files),
            len(pr_diff.changed_symbols),
        )

        # Step 2: Search org-wide for downstream references
        all_downstream_refs = []
        source_repo = f"{owner}/{repo}"

        # Search for each changed symbol
        for i, symbol in enumerate(pr_diff.changed_symbols):
            if symbol.change_type in ("removed", "renamed"):
                search_name = symbol.old_name if symbol.old_name else symbol.name
            else:
                search_name = symbol.name

            # Skip common/generic names that would produce too many results
            if len(search_name) < 5 or search_name.lower() in (
                "queue", "model", "email", "error", "provider", "service",
                "client", "config", "utils", "admin", "views", "tests",
                "settings", "models", "router", "logger", "handler",
                "manager", "factory", "helper", "context", "serializer",
                "field", "value", "state", "status", "action", "event",
                "result", "response", "request", "command", "query",
                "partial", "complete", "completed", "pending", "active",
                "enabled", "disabled", "default", "message", "description",
                "provider_name", "created_at", "updated_at", "deleted_at",
                "is_active", "is_deleted", "created", "updated",
                "transaction_count", "batch_date_start", "batch_date_end",
                "is_historical", "transactions", "connector_id",
            ):
                logger.info("Skipping generic symbol '%s'", search_name)
                continue

            if i > 0:
                time.sleep(2)  # respect GitHub code search rate limits
            refs = self.github.search_org_for_symbol(search_name)
            # Filter out self-references
            external_refs = [r for r in refs if r.repo_full_name != source_repo]
            all_downstream_refs.extend(external_refs)
            logger.info("Symbol '%s': found %d external references", search_name, len(external_refs))

        # Search for package consumers if dependency files changed
        # (Skip for now if we've already found downstream refs — avoids rate limiting)
        if pr_diff.removed_dependencies and not all_downstream_refs:
            for dep in pr_diff.removed_dependencies:
                try:
                    time.sleep(2)
                    refs = self.github.search_package_consumers(dep)
                    external_refs = [r for r in refs if r.repo_full_name != source_repo]
                    all_downstream_refs.extend(external_refs)
                except Exception as e:
                    logger.warning("Skipping package consumer search for '%s': %s", dep, e)

        # Search for other repos that use the same packages being changed
        # (shows which services share this dependency and may need the same upgrade)
        shared_pkg_refs = []
        if pr_diff.package_changes and not all_downstream_refs:
            for pc in pr_diff.package_changes:
                try:
                    time.sleep(2)
                    refs = self.github.search_package_consumers(pc.name)
                    external_refs = [r for r in refs if r.repo_full_name != source_repo]
                    shared_pkg_refs.extend(external_refs)
                    logger.info("Package '%s': used by %d other repos", pc.name, len(external_refs))
                except Exception as e:
                    logger.warning("Skipping shared-package search for '%s': %s", pc.name, e)
            # Add to downstream refs — these are "shared dependency" impacts
            all_downstream_refs.extend(shared_pkg_refs)

        # Build set of repos from shared-package search
        shared_pkg_repos = {r.repo_full_name for r in shared_pkg_refs} if pr_diff.package_changes else set()

        # Step 3: Deduplicate and group references by repo
        seen_refs = set()
        unique_downstream_refs = []
        for ref in all_downstream_refs:
            key = (ref.repo_full_name, ref.file_path, ref.symbol)
            if key not in seen_refs:
                seen_refs.add(key)
                unique_downstream_refs.append(ref)
        all_downstream_refs = unique_downstream_refs

        downstream_by_repo: dict[str, DownstreamImpact] = {}
        for ref in all_downstream_refs:
            if ref.repo_full_name not in downstream_by_repo:
                impact_type = "shared-dependency" if ref.repo_full_name in shared_pkg_repos else "unknown"
                downstream_by_repo[ref.repo_full_name] = DownstreamImpact(
                    repo=ref.repo_full_name,
                    files=[],
                    symbols_matched=[],
                    impact_type=impact_type,
                )
            impact = downstream_by_repo[ref.repo_full_name]
            if ref.file_path not in impact.files:
                impact.files.append(ref.file_path)
            if ref.symbol not in impact.symbols_matched:
                impact.symbols_matched.append(ref.symbol)

        # Step 3b: Vulnerability scan + incident history for current repo only
        all_vulnerabilities = []
        all_repo_incidents = []

        # Build set of packages being changed in this PR
        changed_pkg_names = {re.sub(r"[-_.]+", "-", pc.name).lower() for pc in pr_diff.package_changes}
        updated_pkg_names = {
            re.sub(r"[-_.]+", "-", pc.name).lower()
            for pc in pr_diff.package_changes if pc.change_type == "updated"
        }

        try:
            vulns = self.github.get_vulnerability_alerts(source_repo)
            for v in vulns:
                pkg_normalized = re.sub(r"[-_.]+", "-", v.package).lower()
                if pkg_normalized in updated_pkg_names:
                    pr_impact = "potentially_resolved"
                elif pkg_normalized in changed_pkg_names:
                    pr_impact = "affected"
                else:
                    pr_impact = "existing"
                all_vulnerabilities.append({
                    "repo": source_repo.split("/")[-1],
                    "package": v.package,
                    "severity": v.severity,
                    "summary": v.summary,
                    "patched_version": v.patched_version,
                    "pr_impact": pr_impact,
                })
        except Exception as e:
            logger.warning("Vulnerability scan failed for %s: %s", source_repo, e)

        try:
            incs = self.github.get_recent_incidents(
                source_repo,
                changed_files=set(pr_diff.changed_files),
                package_names={pc.name for pc in pr_diff.package_changes},
            )
            for inc in incs:
                all_repo_incidents.append({
                    "repo": source_repo.split("/")[-1],
                    "title": inc.title,
                    "url": inc.url,
                    "state": inc.state,
                    "date": inc.created_at,
                    "labels": inc.labels,
                })
        except Exception as e:
            logger.warning("Incident search failed for %s: %s", source_repo, e)

        if all_vulnerabilities:
            logger.info("Found %d vulnerability alerts in %s", len(all_vulnerabilities), source_repo)
        if all_repo_incidents:
            logger.info("Found %d recent incidents in %s", len(all_repo_incidents), source_repo)

        # Step 4: Query Datadog for runtime dependencies (if configured)
        runtime_deps = []
        incidents = []
        if self.datadog:
            try:
                svc_info = self.datadog.get_service_dependencies(repo)
                for dep in svc_info.downstream + svc_info.upstream:
                    runtime_deps.append(
                        {
                            "service": dep.service_name,
                            "direction": dep.direction,
                            "type": dep.dependency_type,
                        }
                    )

                # Check incident history for affected services
                affected_services = set()
                affected_services.add(repo)
                for impact in downstream_by_repo.values():
                    svc_name = impact.repo.split("/")[-1]
                    affected_services.add(svc_name)

                for svc in affected_services:
                    svc_incidents = self.datadog.get_incidents(svc)
                    for inc in svc_incidents:
                        incidents.append(
                            {
                                "title": inc.title,
                                "severity": inc.severity,
                                "date": inc.created_at,
                                "ttr": inc.time_to_resolve,
                                "service": inc.service,
                            }
                        )
            except Exception as e:
                logger.warning("Datadog queries failed: %s", e)

        # Step 5: AI risk analysis (or heuristic fallback)
        changed_symbols_dicts = [
            {"name": s.name, "change_type": s.change_type, "old_name": s.old_name}
            for s in pr_diff.changed_symbols
        ]
        downstream_refs_dicts = [
            {"repo": r.repo_full_name, "file": r.file_path, "symbol": r.symbol}
            for r in all_downstream_refs
        ]

        if self.ai:
            # Summarize diff (first 3000 chars of changed lines)
            diff_lines = [
                line for line in pr_diff.diff_text.split("\n")
                if line.startswith("+") or line.startswith("-")
            ]
            diff_summary = "\n".join(diff_lines[:100])

            ai_result = self.ai.analyze(
                pr_title=pr_diff.title,
                pr_description=pr_diff.description,
                diff_summary=diff_summary,
                changed_symbols=changed_symbols_dicts,
                downstream_refs=downstream_refs_dicts,
                runtime_deps=runtime_deps if runtime_deps else None,
                incidents=incidents if incidents else None,
            )
        else:
            ai_result = self._heuristic_analysis(
                pr_diff, all_downstream_refs, downstream_by_repo, all_vulnerabilities
            )

        # Step 6: Enrich downstream impacts with AI deploy order
        for step in ai_result.deploy_order:
            step_repo = step.get("repo", "")
            # Match against full repo name or short name
            for repo_name, impact in downstream_by_repo.items():
                short_name = repo_name.split("/")[-1]
                if step_repo in (repo_name, short_name):
                    impact.deploy_order = step.get("step")
                    impact.blocking = step.get("blocking", False)
                    impact.impact_type = "breaking" if step.get("blocking") else "non-breaking"

        # Attach incidents to downstream impacts
        for inc in incidents:
            for impact in downstream_by_repo.values():
                svc = impact.repo.split("/")[-1]
                if svc in inc.get("service", ""):
                    impact.incident_history.append(inc)

        # Step 7: Build report
        downstream_list = sorted(
            downstream_by_repo.values(),
            key=lambda x: (not x.blocking, x.deploy_order or 999),
        )

        package_changes_dicts = [
            {"name": pc.name, "change_type": pc.change_type,
             "old_version": pc.old_version, "new_version": pc.new_version}
            for pc in pr_diff.package_changes
        ]

        mermaid = generate_mermaid_dag(
            pr_repo=source_repo,
            deploy_order=ai_result.deploy_order,
            downstream=downstream_list,
            package_changes=package_changes_dicts,
            vulnerabilities=all_vulnerabilities,
            repo_incidents=all_repo_incidents,
        )

        report = BlastRadiusReport(
            pr_url=f"https://github.com/{owner}/{repo}/pull/{pr_number}",
            pr_title=pr_diff.title,
            risk_level=ai_result.risk_level,
            risk_reason=ai_result.risk_reason,
            downstream_impacts=downstream_list,
            deploy_order=ai_result.deploy_order,
            warnings=ai_result.warnings,
            safe_to_merge=ai_result.safe_to_merge,
            runtime_deps=runtime_deps,
            incidents=incidents,
            mermaid_dag=mermaid,
            vulnerabilities=all_vulnerabilities,
            repo_incidents=all_repo_incidents,
            package_changes=package_changes_dicts,
        )

        return format_report(report)

    def _heuristic_analysis(self, pr_diff, downstream_refs, downstream_by_repo, vulnerabilities=None):
        """Rule-based risk analysis when OpenAI is not available."""
        from .ai_analyzer import RiskAnalysis

        num_downstream = len(downstream_by_repo)
        has_removals = any(s.change_type == "removed" for s in pr_diff.changed_symbols)
        has_renames = any(s.change_type == "renamed" for s in pr_diff.changed_symbols)
        critical_vulns = len([v for v in (vulnerabilities or []) if v.get("severity") == "critical"])
        high_vulns = len([v for v in (vulnerabilities or []) if v.get("severity") == "high"])

        # Determine risk level heuristically
        if num_downstream == 0:
            risk_level = "LOW"
            reason = "No downstream services reference the changed symbols."
            safe = True
        elif has_removals or has_renames:
            if num_downstream >= 3:
                risk_level = "HIGH"
                reason = f"Breaking changes (removals/renames) affect {num_downstream} downstream repos."
                safe = False
            else:
                risk_level = "MEDIUM"
                reason = f"Breaking changes detected in {num_downstream} downstream repo(s)."
                safe = False
        elif num_downstream >= 5:
            risk_level = "HIGH"
            reason = f"{num_downstream} downstream repos reference changed symbols."
            safe = False
        elif num_downstream >= 2:
            risk_level = "MEDIUM"
            reason = f"{num_downstream} downstream repos reference changed symbols."
            safe = True
        else:
            risk_level = "LOW"
            reason = f"Only {num_downstream} downstream repo(s) affected, no breaking changes detected."
            safe = True

        # Build simple deploy order
        deploy_order = []
        warnings = []
        step = 1
        blocking_repos = []
        non_blocking_repos = []

        for repo_name, impact in downstream_by_repo.items():
            if has_removals or has_renames:
                blocking_repos.append(repo_name)
            else:
                non_blocking_repos.append(repo_name)

        for repo_name in blocking_repos:
            deploy_order.append({
                "step": step,
                "repo": repo_name.split("/")[-1],
                "action": "Update references before merging this PR",
                "blocking": True,
            })
            step += 1

        if deploy_order:
            deploy_order.append({
                "step": step,
                "repo": f"{pr_diff.owner}/{pr_diff.repo}",
                "action": "Merge this PR",
                "blocking": False,
            })

        if has_removals:
            warnings.append("This PR removes symbols that are referenced in downstream repos.")
        if has_renames:
            warnings.append("This PR renames symbols — downstream repos may need updates.")
        if not warnings and num_downstream > 0:
            warnings.append("Changes appear non-breaking but downstream repos reference modified code.")

        # Factor in vulnerabilities
        if critical_vulns > 0:
            warnings.append(f"🚨 {critical_vulns} CRITICAL vulnerabilities in downstream repos — coordinate patching!")
            if risk_level == "LOW":
                risk_level = "MEDIUM"
                reason += f" However, {critical_vulns} critical vulnerabilities exist in downstream repos."
            elif risk_level == "MEDIUM":
                risk_level = "HIGH"
                reason += f" Additionally, {critical_vulns} critical vulnerabilities increase risk."
        elif high_vulns > 0:
            warnings.append(f"⚠️ {high_vulns} HIGH severity vulnerabilities in downstream repos.")

        return RiskAnalysis(
            risk_level=risk_level,
            risk_reason=reason,
            breaking_changes=[
                {"symbol": s.name, "reason": f"Symbol {s.change_type}"}
                for s in pr_diff.changed_symbols
                if s.change_type in ("removed", "renamed")
            ],
            deploy_order=deploy_order,
            warnings=warnings,
            safe_to_merge=safe,
        )
