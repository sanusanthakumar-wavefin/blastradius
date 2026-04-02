"""CLI entrypoint for BlastRadius — run analysis from command line or GitHub Actions."""

from __future__ import annotations

import argparse
import logging
import os
import sys

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

from .analyzer import BlastRadiusAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="BlastRadius — PR Impact Analyzer")
    parser.add_argument("--owner", required=True, help="Repository owner (e.g., waveaccounting)")
    parser.add_argument("--repo", required=True, help="Repository name (e.g., api-integrations)")
    parser.add_argument("--pr", required=True, type=int, help="PR number (e.g., 416)")
    parser.add_argument("--output", default="blastradius_report.md", help="Output file path")
    parser.add_argument("--org", default="waveaccounting", help="GitHub org to search")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    parser.add_argument("--comment", action="store_true", help="Post report as a PR comment on GitHub")
    args = parser.parse_args()

    github_token = os.environ.get("GITHUB_TOKEN")
    openai_key = os.environ.get("OPENAI_API_KEY")
    dd_api_key = os.environ.get("DD_API_KEY")
    dd_app_key = os.environ.get("DD_APP_KEY")

    if not github_token:
        logger.error("GITHUB_TOKEN environment variable is required")
        sys.exit(1)
    if not openai_key:
        logger.warning("OPENAI_API_KEY not set — AI risk analysis will be skipped")

    analyzer = BlastRadiusAnalyzer(
        github_token=github_token,
        openai_api_key=openai_key,
        org=args.org,
        dd_api_key=dd_api_key,
        dd_app_key=dd_app_key,
        ai_model=args.model,
    )

    report = analyzer.analyze_pr(args.owner, args.repo, args.pr)

    # Write to file
    with open(args.output, "w") as f:
        f.write(report)
    logger.info("Report written to %s", args.output)

    # Post as PR comment if requested
    if args.comment:
        try:
            from github import Auth, Github

            gh = Github(auth=Auth.Token(github_token), retry=None)
            repo_obj = gh.get_repo(f"{args.owner}/{args.repo}")
            pr_obj = repo_obj.get_pull(args.pr)

            # Delete any previous BlastRadius comment to avoid spam
            for comment in pr_obj.get_issue_comments():
                if comment.body and "BlastRadius Report" in comment.body:
                    comment.delete()
                    logger.info("Deleted previous BlastRadius comment")

            pr_obj.create_issue_comment(report)
            logger.info(
                "Posted report as comment on %s/%s#%d",
                args.owner, args.repo, args.pr,
            )
        except Exception as e:
            logger.error("Failed to post PR comment: %s", e)
            sys.exit(1)

    # Also print to stdout
    print(report)


if __name__ == "__main__":
    main()
