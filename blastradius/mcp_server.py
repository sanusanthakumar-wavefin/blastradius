"""BlastRadius MCP Server — interactive blast radius analysis from VS Code Copilot."""

from __future__ import annotations

import logging
import os
import re

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

from mcp.server.fastmcp import FastMCP

from .analyzer import BlastRadiusAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("BlastRadius", instructions="Analyze PRs for cross-repo downstream impact.")


def _get_analyzer() -> BlastRadiusAnalyzer:
    """Create analyzer from environment variables."""
    github_token = os.environ.get("GITHUB_TOKEN", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    dd_api_key = os.environ.get("DD_API_KEY")
    dd_app_key = os.environ.get("DD_APP_KEY")
    dd_site = os.environ.get("DD_SITE", "datadoghq.com")
    org = os.environ.get("GITHUB_ORG", "waveaccounting")

    if not github_token:
        raise ValueError("GITHUB_TOKEN environment variable is required")

    return BlastRadiusAnalyzer(
        github_token=github_token,
        openai_api_key=openai_key if openai_key else None,
        org=org,
        dd_api_key=dd_api_key,
        dd_app_key=dd_app_key,
        dd_site=dd_site,
    )


@mcp.tool()
def analyze_pr(pr_url: str) -> str:
    """Analyze a GitHub PR for cross-repo blast radius.

    Scans org-wide code for downstream references to changed symbols,
    queries Datadog for runtime dependencies, checks incident history,
    and generates a risk report with deployment order.

    Args:
        pr_url: Full GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)
                or short form (owner/repo#123)
    """
    owner, repo, pr_number = _parse_pr_url(pr_url)
    analyzer = _get_analyzer()
    return analyzer.analyze_pr(owner, repo, pr_number)


@mcp.tool()
def analyze_pr_by_parts(owner: str, repo: str, pr_number: int) -> str:
    """Analyze a GitHub PR for cross-repo blast radius using explicit parameters.

    Args:
        owner: Repository owner (e.g., "waveaccounting")
        repo: Repository name (e.g., "api-integrations")
        pr_number: PR number (e.g., 416)
    """
    analyzer = _get_analyzer()
    return analyzer.analyze_pr(owner, repo, pr_number)


def _parse_pr_url(pr_url: str) -> tuple[str, str, int]:
    """Parse a PR URL or short form into (owner, repo, pr_number)."""
    # Full URL: https://github.com/owner/repo/pull/123
    url_match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)", pr_url)
    if url_match:
        return url_match.group(1), url_match.group(2), int(url_match.group(3))

    # Short form: owner/repo#123
    short_match = re.match(r"([^/]+)/([^#]+)#(\d+)", pr_url)
    if short_match:
        return short_match.group(1), short_match.group(2), int(short_match.group(3))

    raise ValueError(f"Cannot parse PR reference: {pr_url}. Use 'owner/repo#123' or full GitHub URL.")


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
