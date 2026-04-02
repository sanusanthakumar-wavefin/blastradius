"""Datadog client for BlastRadius — service dependencies and incident history."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)


@dataclass
class ServiceDependency:
    """A runtime service dependency from Datadog APM."""

    service_name: str
    direction: str  # "upstream" or "downstream"
    dependency_type: str  # "grpc", "http", "database", "cache", "queue"


@dataclass
class IncidentRecord:
    """A past incident correlated with a service or file."""

    title: str
    severity: str
    created_at: str
    resolved_at: str | None
    service: str
    url: str | None = None
    time_to_resolve: str | None = None


@dataclass
class ServiceInfo:
    """Aggregated Datadog info for a service."""

    service_name: str
    downstream: list[ServiceDependency] = field(default_factory=list)
    upstream: list[ServiceDependency] = field(default_factory=list)
    incidents: list[IncidentRecord] = field(default_factory=list)
    error_rate_24h: float | None = None


class DatadogClient:
    """Queries Datadog for runtime service dependencies and incident history."""

    def __init__(self, api_key: str, app_key: str, site: str = "datadoghq.com"):
        self.api_key = api_key
        self.app_key = app_key
        self.base_url = f"https://api.{site}/api"
        self.headers = {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        }

    def get_service_dependencies(self, service: str) -> ServiceInfo:
        """Get upstream and downstream dependencies for a service from APM."""
        info = ServiceInfo(service_name=service)

        # Try the service with common sub-service suffixes
        suffixes = ["", ".web", ".rpcx", ".connector-import", ".connector-export", ".taskpool-worker"]
        for suffix in suffixes:
            svc = f"{service}{suffix}"
            downstream = self._get_dependencies(svc, "downstream")
            upstream = self._get_dependencies(svc, "upstream")
            info.downstream.extend(downstream)
            info.upstream.extend(upstream)

        # Deduplicate
        seen_down = set()
        info.downstream = [d for d in info.downstream if d.service_name not in seen_down and not seen_down.add(d.service_name)]
        seen_up = set()
        info.upstream = [u for u in info.upstream if u.service_name not in seen_up and not seen_up.add(u.service_name)]

        return info

    def get_incidents(self, service: str, lookback_days: int = 90) -> list[IncidentRecord]:
        """Search for incidents related to a service in the last N days."""
        incidents = []
        try:
            url = f"{self.base_url}/v2/incidents"
            params = {
                "page[size]": 25,
                "filter[query]": service,
            }
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    created = attrs.get("created", "")
                    if created:
                        try:
                            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                            if created_dt < cutoff:
                                continue
                        except ValueError:
                            pass

                    resolved = attrs.get("resolved")
                    ttr = None
                    if created and resolved:
                        try:
                            c = datetime.fromisoformat(created.replace("Z", "+00:00"))
                            r = datetime.fromisoformat(resolved.replace("Z", "+00:00"))
                            delta = r - c
                            hours = delta.total_seconds() / 3600
                            ttr = f"{hours:.1f}hr" if hours >= 1 else f"{delta.total_seconds() / 60:.0f}min"
                        except ValueError:
                            pass

                    incidents.append(
                        IncidentRecord(
                            title=attrs.get("title", "Unknown"),
                            severity=attrs.get("severity", "unknown"),
                            created_at=created[:10] if created else "unknown",
                            resolved_at=resolved[:10] if resolved else None,
                            service=service,
                            url=attrs.get("public_id"),
                            time_to_resolve=ttr,
                        )
                    )
            else:
                logger.warning("Incidents API returned %d for %s", resp.status_code, service)
        except Exception as e:
            logger.warning("Failed to fetch incidents for %s: %s", service, e)
        return incidents

    def get_error_rate(self, service: str) -> float | None:
        """Get 24h error rate for a service from Datadog metrics."""
        try:
            now = int(datetime.now(timezone.utc).timestamp())
            one_day_ago = now - 86400
            url = f"{self.base_url}/v1/query"
            params = {
                "from": one_day_ago,
                "to": now,
                "query": f"sum:trace.http.request.errors{{service:{service}}}.as_rate()",
            }
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                series = data.get("series", [])
                if series and series[0].get("pointlist"):
                    points = series[0]["pointlist"]
                    avg = sum(p[1] for p in points if p[1] is not None) / max(len(points), 1)
                    return round(avg, 4)
        except Exception as e:
            logger.warning("Failed to get error rate for %s: %s", service, e)
        return None

    def _get_dependencies(self, service: str, direction: str) -> list[ServiceDependency]:
        """Query APM service dependencies."""
        deps = []
        try:
            url = f"{self.base_url}/v1/service_dependencies"
            # Datadog Service Dependencies API
            if direction == "downstream":
                params = {"service_name": service, "direction": "downstream"}
            else:
                params = {"service_name": service, "direction": "upstream"}

            # Use the APM service map endpoint
            url = f"{self.base_url}/v2/services"
            resp = requests.get(
                f"{self.base_url}/v1/service_dependencies/{service}",
                headers=self.headers,
                params={"direction": direction},
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                for svc in data.get("services", data.get("data", [])):
                    name = svc if isinstance(svc, str) else svc.get("name", svc.get("id", ""))
                    if name:
                        dep_type = self._infer_dep_type(name)
                        deps.append(
                            ServiceDependency(
                                service_name=name,
                                direction=direction,
                                dependency_type=dep_type,
                            )
                        )
        except Exception as e:
            logger.debug("Dependency lookup failed for %s (%s): %s", service, direction, e)
        return deps

    @staticmethod
    def _infer_dep_type(service_name: str) -> str:
        """Infer dependency type from service name conventions."""
        name = service_name.lower()
        if "db" in name or "defaultdb" in name or "shard" in name:
            return "database"
        if "cache" in name or "redis" in name:
            return "cache"
        if "queue" in name or "sqs" in name or "consumer" in name:
            return "queue"
        if "rpc" in name or "grpc" in name:
            return "grpc"
        return "http"
