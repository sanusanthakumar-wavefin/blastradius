"""AI analyzer for BlastRadius — risk classification and deploy order using OpenAI."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from openai import OpenAI

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are BlastRadius, an expert software deployment risk analyzer.
Given a PR diff, a list of downstream services/repos that reference changed symbols,
and optional Datadog runtime dependency data, you must:

1. Classify the risk level: LOW, MEDIUM, HIGH, or CRITICAL
2. Determine if there's a required deployment order
3. Identify breaking vs non-breaking changes
4. Flag any services that MUST be updated before this PR is deployed
5. Note any past incidents related to the affected services

Output a JSON object with this schema:
{
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "risk_reason": "One sentence explaining the risk level",
  "breaking_changes": [{"symbol": "...", "reason": "..."}],
  "deploy_order": [{"step": 1, "repo": "...", "action": "...", "blocking": true}],
  "warnings": ["..."],
  "safe_to_merge_without_coordination": true/false
}

Be concise. Focus on actionable information. If there are no downstream impacts, say so clearly."""


@dataclass
class RiskAnalysis:
    """Result of AI risk analysis."""

    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_reason: str
    breaking_changes: list[dict] = field(default_factory=list)
    deploy_order: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    safe_to_merge: bool = True
    raw_response: str = ""


class AIAnalyzer:
    """Uses OpenAI to classify risk and generate deployment recommendations."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def analyze(
        self,
        pr_title: str,
        pr_description: str,
        diff_summary: str,
        changed_symbols: list[dict],
        downstream_refs: list[dict],
        runtime_deps: list[dict] | None = None,
        incidents: list[dict] | None = None,
    ) -> RiskAnalysis:
        """Analyze a PR's blast radius and return risk classification."""

        user_prompt = self._build_prompt(
            pr_title, pr_description, diff_summary, changed_symbols,
            downstream_refs, runtime_deps, incidents,
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=2000,
            )

            raw = response.choices[0].message.content or "{}"
            data = json.loads(raw)

            return RiskAnalysis(
                risk_level=data.get("risk_level", "MEDIUM"),
                risk_reason=data.get("risk_reason", "Unable to determine"),
                breaking_changes=data.get("breaking_changes", []),
                deploy_order=data.get("deploy_order", []),
                warnings=data.get("warnings", []),
                safe_to_merge=data.get("safe_to_merge_without_coordination", True),
                raw_response=raw,
            )

        except Exception as e:
            logger.error("AI analysis failed: %s", e)
            return RiskAnalysis(
                risk_level="UNKNOWN",
                risk_reason=f"AI analysis failed: {e}",
                safe_to_merge=False,
            )

    def _build_prompt(
        self,
        pr_title: str,
        pr_description: str,
        diff_summary: str,
        changed_symbols: list[dict],
        downstream_refs: list[dict],
        runtime_deps: list[dict] | None,
        incidents: list[dict] | None,
    ) -> str:
        sections = [
            f"## PR: {pr_title}",
            f"Description: {pr_description[:500]}",
            f"\n## Diff Summary (key changes):\n{diff_summary[:3000]}",
        ]

        if changed_symbols:
            sections.append("\n## Changed Symbols:")
            for sym in changed_symbols[:30]:
                old = f" (was: {sym['old_name']})" if sym.get("old_name") else ""
                sections.append(f"- [{sym['change_type']}] {sym['name']}{old}")

        if downstream_refs:
            sections.append(f"\n## Downstream References Found ({len(downstream_refs)} matches across org):")
            # Group by repo
            by_repo: dict[str, list] = {}
            for ref in downstream_refs:
                repo = ref["repo"]
                by_repo.setdefault(repo, []).append(ref)
            for repo, refs in by_repo.items():
                files = ", ".join(set(r["file"] for r in refs[:5]))
                sections.append(f"- **{repo}**: {files}")
        else:
            sections.append("\n## No downstream references found in other repos.")

        if runtime_deps:
            sections.append("\n## Datadog Runtime Dependencies:")
            for dep in runtime_deps:
                sections.append(f"- {dep['direction']}: {dep['service']} ({dep['type']})")

        if incidents:
            sections.append("\n## Incident History (last 90 days):")
            for inc in incidents:
                ttr = f", TTR: {inc['ttr']}" if inc.get("ttr") else ""
                sections.append(f"- [{inc['severity']}] {inc['title']} ({inc['date']}{ttr})")

        return "\n".join(sections)
