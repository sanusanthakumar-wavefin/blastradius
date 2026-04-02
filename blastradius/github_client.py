"""GitHub client for BlastRadius — PR reading, org-wide code search, file contents."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from github import Auth, Github
from github.ContentFile import ContentFile
from github.PullRequest import PullRequest

logger = logging.getLogger(__name__)


@dataclass
class ChangedSymbol:
    """A symbol (class, function, import, protobuf message, etc.) that was changed in a PR."""

    name: str
    change_type: str  # "removed", "added", "renamed"
    file_path: str
    old_name: str | None = None  # for renames


@dataclass
class PRDiff:
    """Parsed representation of a PR diff."""

    owner: str
    repo: str
    pr_number: int
    title: str
    description: str
    changed_files: list[str]
    diff_text: str
    changed_symbols: list[ChangedSymbol] = field(default_factory=list)
    added_dependencies: list[str] = field(default_factory=list)
    removed_dependencies: list[str] = field(default_factory=list)


@dataclass
class DownstreamRef:
    """A reference to a changed symbol found in another repo."""

    repo_full_name: str
    file_path: str
    symbol: str
    matched_fragment: str


@dataclass
class VersionPin:
    """Version constraint info from a downstream repo's dependency file."""

    repo_full_name: str
    file_path: str
    current_version: str
    constraint: str  # e.g., "^2.2.3", "==4.0.0"
    will_auto_update: bool


@dataclass
class VulnerabilityAlert:
    """A Dependabot / security vulnerability alert on a repo."""

    repo_full_name: str
    package: str
    severity: str  # "critical", "high", "medium", "low"
    summary: str
    advisory_url: str


@dataclass
class RepoIncident:
    """A recent incident/hotfix/outage issue found in a repo."""

    repo_full_name: str
    title: str
    url: str
    state: str
    created_at: str
    labels: list[str]


class GitHubClient:
    """Interacts with GitHub API for blast radius analysis."""

    def __init__(self, token: str, org: str = "waveaccounting"):
        self.gh = Github(auth=Auth.Token(token), retry=None)
        self.org = org

    def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> PRDiff:
        """Read a PR and extract its diff, changed files, and symbols."""
        repository = self.gh.get_repo(f"{owner}/{repo}")
        pr: PullRequest = repository.get_pull(pr_number)

        changed_files = [f.filename for f in pr.get_files()]

        # Get raw diff
        diff_text = ""
        for f in pr.get_files():
            if f.patch:
                diff_text += f"--- a/{f.filename}\n+++ b/{f.filename}\n{f.patch}\n\n"

        # Extract changed symbols from diff
        changed_symbols = self._extract_symbols_from_diff(diff_text, changed_files)

        # Extract dependency changes
        added_deps, removed_deps = self._extract_dependency_changes(diff_text, changed_files)

        return PRDiff(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            title=pr.title,
            description=pr.body or "",
            changed_files=changed_files,
            diff_text=diff_text,
            changed_symbols=changed_symbols,
            added_dependencies=added_deps,
            removed_dependencies=removed_deps,
        )

    def search_org_for_symbol(self, symbol: str) -> list[DownstreamRef]:
        """Search across all org repos for references to a symbol."""
        refs = []
        query = f"{symbol} org:{self.org}"
        try:
            results = self.gh.search_code(query)
            count = 0
            for item in results:
                if count >= 30:  # cap to avoid rate limits / hangs
                    break
                repo_name = item.repository.full_name
                refs.append(
                    DownstreamRef(
                        repo_full_name=repo_name,
                        file_path=item.path,
                        symbol=symbol,
                        matched_fragment="",
                    )
                )
                count += 1
        except Exception as e:
            logger.warning("Code search failed for '%s': %s", symbol, e)
        return refs

    def search_package_consumers(self, package_name: str) -> list[DownstreamRef]:
        """Find all repos that depend on a given package."""
        refs = []
        for filename in ["pyproject.toml", "requirements.txt", "package.json", "Gemfile"]:
            query = f"{package_name} org:{self.org} filename:{filename}"
            try:
                results = self.gh.search_code(query)
                count = 0
                for item in results:
                    if count >= 20:
                        break
                    refs.append(
                        DownstreamRef(
                            repo_full_name=item.repository.full_name,
                            file_path=item.path,
                            symbol=package_name,
                            matched_fragment="",
                        )
                    )
                    count += 1
            except Exception as e:
                logger.warning("Package search failed for '%s' in %s: %s", package_name, filename, e)
        return refs

    def get_vulnerability_alerts(self, repo_full_name: str) -> list[VulnerabilityAlert]:
        """Get Dependabot security alerts for a repo using the REST API."""
        alerts = []
        try:
            # Use the underlying requester to call the Dependabot alerts endpoint
            headers, data = self.gh._Github__requester.requestJsonAndCheck(
                "GET",
                f"/repos/{repo_full_name}/dependabot/alerts",
                parameters={"state": "open", "per_page": 10},
            )
            for alert in data:
                severity = alert.get("security_advisory", {}).get("severity", "unknown")
                summary = alert.get("security_advisory", {}).get("summary", "")
                pkg = alert.get("security_vulnerability", {}).get("package", {}).get("name", "unknown")
                url = alert.get("html_url", "")
                alerts.append(VulnerabilityAlert(
                    repo_full_name=repo_full_name,
                    package=pkg,
                    severity=severity,
                    summary=summary,
                    advisory_url=url,
                ))
        except Exception as e:
            logger.debug("Dependabot alerts not available for %s: %s", repo_full_name, e)
        return alerts

    def get_recent_incidents(self, repo_full_name: str) -> list[RepoIncident]:
        """Search for recent incident/hotfix/outage issues in a repo using the search API."""
        incidents = []
        try:
            # Single search query instead of per-label lookups (avoids rate limits)
            label_terms = " ".join(
                f"label:{l}" for l in ["incident", "hotfix", "outage", "sev1", "sev2", "P0", "P1"]
            )
            query = f"repo:{repo_full_name} is:issue {label_terms}"
            results = self.gh.search_issues(query, sort="created", order="desc")
            count = 0
            for issue in results:
                if count >= 10:
                    break
                incidents.append(RepoIncident(
                    repo_full_name=repo_full_name,
                    title=issue.title,
                    url=issue.html_url,
                    state=issue.state,
                    created_at=issue.created_at.strftime("%Y-%m-%d"),
                    labels=[l.name for l in issue.labels],
                ))
                count += 1
        except Exception as e:
            logger.debug("Incident search failed for %s: %s", repo_full_name, e)
        return incidents

    def get_file_content(self, repo_full_name: str, path: str) -> str | None:
        """Read a file from a remote repo."""
        try:
            repository = self.gh.get_repo(repo_full_name)
            content: ContentFile = repository.get_contents(path)
            if isinstance(content, list):
                return None
            return content.decoded_content.decode("utf-8")
        except Exception as e:
            logger.warning("Failed to read %s/%s: %s", repo_full_name, path, e)
            return None

    def get_version_pins(self, package_name: str, downstream_refs: list[DownstreamRef]) -> list[VersionPin]:
        """Check what version each downstream repo pins for a package."""
        pins = []
        seen_repos = set()
        for ref in downstream_refs:
            if ref.repo_full_name in seen_repos:
                continue
            seen_repos.add(ref.repo_full_name)

            content = self.get_file_content(ref.repo_full_name, ref.file_path)
            if not content:
                continue

            version_info = self._parse_version_constraint(content, package_name)
            if version_info:
                pins.append(
                    VersionPin(
                        repo_full_name=ref.repo_full_name,
                        file_path=ref.file_path,
                        current_version=version_info["version"],
                        constraint=version_info["constraint"],
                        will_auto_update=version_info["auto_update"],
                    )
                )
        return pins

    def _extract_symbols_from_diff(self, diff_text: str, changed_files: list[str]) -> list[ChangedSymbol]:
        """Extract class names, function names, imports, protobuf messages from diff."""
        symbols = []

        # Pattern: lines removed (starting with -)
        removed_imports = re.findall(r"^-\s*(?:from\s+\S+\s+)?import\s+(.+)", diff_text, re.MULTILINE)
        added_imports = re.findall(r"^\+\s*(?:from\s+\S+\s+)?import\s+(.+)", diff_text, re.MULTILINE)

        # Extract individual symbol names from import lines
        removed_names = set()
        for imp in removed_imports:
            for name in re.findall(r"\b([A-Z][A-Za-z0-9_]+)\b", imp):
                removed_names.add(name)

        added_names = set()
        for imp in added_imports:
            for name in re.findall(r"\b([A-Z][A-Za-z0-9_]+)\b", imp):
                added_names.add(name)

        # Detect renames: removed name has a corresponding added name with similar structure
        renamed = set()
        for removed in removed_names:
            for added in added_names:
                if removed != added and self._is_likely_rename(removed, added):
                    symbols.append(
                        ChangedSymbol(
                            name=added,
                            change_type="renamed",
                            file_path="(from diff)",
                            old_name=removed,
                        )
                    )
                    renamed.add(removed)
                    renamed.add(added)

        # Pure removals
        for name in removed_names - renamed:
            symbols.append(ChangedSymbol(name=name, change_type="removed", file_path="(from diff)"))

        # Pure additions
        for name in added_names - renamed:
            symbols.append(ChangedSymbol(name=name, change_type="added", file_path="(from diff)"))

        # Function/method renames from def lines
        removed_defs = set(re.findall(r"^-\s*def\s+(\w+)", diff_text, re.MULTILINE))
        added_defs = set(re.findall(r"^\+\s*def\s+(\w+)", diff_text, re.MULTILINE))
        for name in removed_defs - added_defs:
            symbols.append(ChangedSymbol(name=name, change_type="removed", file_path="(from diff)"))

        # gRPC/protobuf service method changes
        grpc_methods = re.findall(r"^-.*self\.client\.(\w+)\(", diff_text, re.MULTILINE)
        for method in grpc_methods:
            if method not in [s.name for s in symbols]:
                symbols.append(ChangedSymbol(name=method, change_type="removed", file_path="(from diff)"))

        # Class/enum definitions added or removed
        removed_classes = set(re.findall(r"^-\s*class\s+(\w+)", diff_text, re.MULTILINE))
        added_classes = set(re.findall(r"^\+\s*class\s+(\w+)", diff_text, re.MULTILINE))
        for name in removed_classes - added_classes:
            if name not in [s.name for s in symbols]:
                symbols.append(ChangedSymbol(name=name, change_type="removed", file_path="(from diff)"))
        for name in added_classes - removed_classes:
            if name not in [s.name for s in symbols]:
                symbols.append(ChangedSymbol(name=name, change_type="added", file_path="(from diff)"))

        # Enum members (UPPER_CASE = "value") and constants
        removed_enums = set(re.findall(r"^-\s+([A-Z][A-Z0-9_]{2,})\s*=", diff_text, re.MULTILINE))
        added_enums = set(re.findall(r"^\+\s+([A-Z][A-Z0-9_]{2,})\s*=", diff_text, re.MULTILINE))
        for name in removed_enums - added_enums:
            if name not in [s.name for s in symbols]:
                symbols.append(ChangedSymbol(name=name, change_type="removed", file_path="(from diff)"))
        for name in added_enums - removed_enums:
            if name not in [s.name for s in symbols]:
                symbols.append(ChangedSymbol(name=name, change_type="added", file_path="(from diff)"))

        # Dataclass/TypedDict field additions/removals (name: Type pattern)
        removed_fields = set(re.findall(r"^-\s+(\w+)\s*:\s*\w+", diff_text, re.MULTILINE))
        added_fields = set(re.findall(r"^\+\s+(\w+)\s*:\s*\w+", diff_text, re.MULTILINE))
        # Filter out common noise (self, return, type, etc.)
        noise = {"self", "return", "type", "status", "str", "int", "bool", "float", "dict", "list", "None"}
        removed_fields -= noise
        added_fields -= noise
        for name in removed_fields - added_fields:
            if name not in [s.name for s in symbols] and len(name) >= 5:
                symbols.append(ChangedSymbol(name=name, change_type="removed", file_path="(from diff)"))
        for name in added_fields - removed_fields:
            if name not in [s.name for s in symbols] and len(name) >= 5:
                symbols.append(ChangedSymbol(name=name, change_type="added", file_path="(from diff)"))

        return symbols

    def _extract_dependency_changes(self, diff_text: str, changed_files: list[str]) -> tuple[list[str], list[str]]:
        """Detect added/removed dependencies from pyproject.toml, requirements.txt, etc."""
        added = []
        removed = []

        dep_files = [f for f in changed_files if f in ("pyproject.toml", "requirements.txt", "package.json")]
        if not dep_files:
            return added, removed

        # Simple heuristic: lines with package names added/removed
        for line in diff_text.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                match = re.search(r'"([a-zA-Z0-9_-]+)"', line)
                if match:
                    added.append(match.group(1))
            elif line.startswith("-") and not line.startswith("---"):
                match = re.search(r'"([a-zA-Z0-9_-]+)"', line)
                if match:
                    removed.append(match.group(1))

        return added, removed

    def _is_likely_rename(self, old: str, new: str) -> bool:
        """Guess if two symbol names are a rename of each other."""
        # e.g., IntegrationsEtsyImportDone -> IntegrationsImportDone
        # One is a substring variant of the other
        old_lower = old.lower()
        new_lower = new.lower()
        if old_lower in new_lower or new_lower in old_lower:
            return True
        # Share a long common substring
        common = self._longest_common_substring(old_lower, new_lower)
        return len(common) > min(len(old), len(new)) * 0.5

    @staticmethod
    def _longest_common_substring(s1: str, s2: str) -> str:
        m = [[0] * (1 + len(s2)) for _ in range(1 + len(s1))]
        longest, x_longest = 0, 0
        for x in range(1, 1 + len(s1)):
            for y in range(1, 1 + len(s2)):
                if s1[x - 1] == s2[y - 1]:
                    m[x][y] = m[x - 1][y - 1] + 1
                    if m[x][y] > longest:
                        longest = m[x][y]
                        x_longest = x
        return s1[x_longest - longest : x_longest]

    @staticmethod
    def _get_fragment(item) -> str:
        """Extract text fragment from a code search result."""
        try:
            for tm in item.text_matches:
                return tm.get("fragment", "")[:200]
        except Exception:
            pass
        return ""

    @staticmethod
    def _parse_version_constraint(content: str, package_name: str) -> dict | None:
        """Parse version constraint from a pyproject.toml or requirements file."""
        for line in content.split("\n"):
            if package_name in line:
                # pyproject.toml style: package = "^2.2.3" or {version = "^2.2.3", ...}
                match = re.search(r'["\']([~^>=<!\d][^"\']*)["\']', line)
                if match:
                    constraint = match.group(1)
                    version = re.search(r"(\d+\.\d+\.\d+)", constraint)
                    auto_update = constraint.startswith("^") or constraint.startswith(">=") or constraint.startswith("~")
                    return {
                        "constraint": constraint,
                        "version": version.group(1) if version else constraint,
                        "auto_update": auto_update,
                    }
        return None
