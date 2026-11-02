"""Tenable Security Center adapter.

This follows the documented Security Center ``/rest`` API and the payload shape
used by pyTenable's ``sc.analysis.vulns``:

* ``GET  /rest/currentUser`` — credential check
* ``POST /rest/analysis``    — CVE / plugin queries (tool ``vulndetails``)
* ``GET  /rest/asset/{id}``  — asset posture
* ``GET  /rest/agent``       — agent inventory (version dependent)

No Security Center appliance was provided in the lab environment, so this
adapter is **not live-validated**. Every run records that fact rather than
silently treating SC data as equivalent to the validated VM path.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from ..config import TenableSCSettings
from ..errors import ConnectorError, NotFoundError, ScopeError
from ..models import AssetRef, Finding, PluginHit
from ..util import (
    as_bool,
    as_float,
    as_int,
    normalize_mac,
    truncate,
    utc_now,
)
from .http import TenableHTTP

LOGGER = logging.getLogger("secops.tenable.sc")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _text(value: Any) -> str | None:
    if isinstance(value, dict):
        return _text(value.get("name") or value.get("id"))
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _split_csv(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _unwrap(payload: Any) -> Any:
    if isinstance(payload, dict) and "response" in payload:
        error_code = payload.get("error_code")
        try:
            error_num = int(error_code) if error_code is not None else 0
        except (TypeError, ValueError):
            error_num = 0
        if error_num:
            raise ConnectorError(
                f"Security Center error {error_code}: {payload.get('error_msg') or 'unknown error'}"
            )
        return payload["response"]
    return payload


class TenableSCClient:
    name = "tenable_sc"
    live = True

    def __init__(
        self,
        settings: TenableSCSettings,
        *,
        page_size: int = 5000,
        max_pages: int = 20,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if not settings.configured:
            raise ConnectorError(
                "Tenable Security Center is not configured; set TENABLE_SC_URL, "
                "TENABLE_SC_ACCESS_KEY and TENABLE_SC_SECRET_KEY"
            )
        self.settings = settings
        self.page_size = page_size
        self.max_pages = max_pages
        kwargs: dict[str, Any] = {}
        if sleep is not None:
            kwargs["sleep"] = sleep
        self.http = TenableHTTP(
            base_url=settings.base_url or "",
            access_key=settings.access_key or "",
            secret_key=settings.secret_key or "",
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_retries=settings.max_retries,
            verify_tls=settings.verify_tls,
            **kwargs,
        )
        self.last_analysis: dict[str, Any] = {}

    # -- health ---------------------------------------------------------

    def health(self) -> dict[str, Any]:
        data = _unwrap(self.http.get_json("/rest/currentUser"))
        user = data if isinstance(data, dict) else {}
        return {
            "ok": True,
            "product": "Tenable Security Center",
            "base_url": self.settings.base_url,
            "account": user.get("username") or user.get("userName") or user.get("name"),
            "user_agent": self.settings.user_agent,
            "adapter_validation": "documented API shape; not live-tested in this environment",
            "retrieved": utc_now(),
        }

    # -- analysis -------------------------------------------------------

    def _analysis(
        self,
        filters: list[dict[str, Any]],
        *,
        offset: int = 0,
        limit: int | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        limit = limit or self.page_size
        body = {
            "type": "vuln",
            "sourceType": "cumulative",
            "query": {
                "type": "vuln",
                "tool": "vulndetails",
                "startOffset": offset,
                "endOffset": offset + limit,
                "filters": filters,
            },
            "sortField": "severity",
            "sortDir": "DESC",
        }
        payload = _unwrap(self.http.post_json("/rest/analysis", body))
        if isinstance(payload, list):
            return payload, len(payload)
        rows = payload.get("results") or []
        total = as_int(payload.get("totalRecords")) or len(rows)
        return rows, total

    def _analysis_paged(self, filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        offset = 0
        total = 0
        for _ in range(self.max_pages):
            page, total = self._analysis(filters, offset=offset)
            rows.extend(page)
            if not page or len(rows) >= total:
                break
            offset += len(page)
        self.last_analysis = {
            "filters": filters,
            "returned": len(rows),
            "total_records": total,
            "retrieved": utc_now(),
        }
        return rows

    def cve_plugin_hits(self, cve: str, date_range: int = 90) -> list[PluginHit]:
        rows: list[dict[str, Any]] = []
        last_error: Exception | None = None
        for filter_name in ("cveID", "cve"):
            try:
                rows = self._analysis_paged(
                    [
                        {
                            "filterName": filter_name,
                            "operator": "=",
                            "value": cve.upper(),
                        }
                    ]
                )
                break
            except ConnectorError as exc:
                last_error = exc
                continue
        if last_error is not None and not rows:
            raise last_error

        by_plugin: dict[int, dict[str, Any]] = {}
        for row in rows:
            plugin_id = as_int(row.get("pluginID") or row.get("pluginId"))
            if not plugin_id:
                continue
            entry = by_plugin.setdefault(
                plugin_id,
                {
                    "name": _text(row.get("pluginName")) or "unknown plugin",
                    "family": _text(row.get("pluginFamily")) or "unknown",
                    "severity": self._severity(row),
                    "assets": set(),
                    "count": 0,
                    "cvss3": as_float(row.get("cvssV3BaseScore")),
                    "cvss2": as_float(row.get("cvssBaseScore")),
                    "vpr": as_float(row.get("vprScore")),
                },
            )
            entry["assets"].add(self._asset_key(row))
            entry["count"] += 1
        hits = [
            PluginHit(
                plugin_id=plugin_id,
                plugin_name=entry["name"],
                family=entry["family"],
                severity=entry["severity"],
                asset_count=len(entry["assets"]),
                finding_count=entry["count"],
                cvss3_base=entry["cvss3"],
                cvss2_base=entry["cvss2"],
                vpr=entry["vpr"],
                state=None,
            )
            for plugin_id, entry in by_plugin.items()
        ]
        hits.sort(
            key=lambda h: (
                -(h.severity if h.severity is not None else -1),
                -(h.vpr if h.vpr is not None else -1),
                h.plugin_id,
            )
        )
        return hits

    def findings_for_plugins(
        self, plugin_ids: list[int], date_range: int = 90
    ) -> list[Finding]:
        ids = sorted({int(pid) for pid in plugin_ids if int(pid) > 0})
        if not ids:
            return []
        rows: list[dict[str, Any]] = []
        for start in range(0, len(ids), 50):
            chunk = ids[start : start + 50]
            rows.extend(
                self._analysis_paged(
                    [
                        {
                            "filterName": "pluginID",
                            "operator": "=",
                            "value": ",".join(str(pid) for pid in chunk),
                        }
                    ]
                )
            )
        findings = [self._parse_finding(row) for row in rows]
        return findings

    def asset_detail(self, asset_uuid: str) -> dict[str, Any]:
        try:
            payload = _unwrap(self.http.get_json(f"/rest/asset/{asset_uuid}"))
        except NotFoundError:
            return {
                "asset_uuid": asset_uuid,
                "_error": "Security Center asset record not found",
                "retrieved": utc_now(),
            }
        data = payload if isinstance(payload, dict) else {}
        return {
            "asset_uuid": str(data.get("id") or asset_uuid),
            "hostname": _text(data.get("name") or data.get("dnsName") or data.get("netbiosName")),
            "fqdn": _split_csv(data.get("dnsName")),
            "ipv4": _split_csv(data.get("ip") or data.get("ipAddress")),
            "mac": normalize_mac(_text(data.get("macAddress"))),
            "os": _split_csv(data.get("operatingSystem") or data.get("os")),
            "has_agent": as_bool(data.get("hasAgent")),
            "agent_name": _text(data.get("agentName")),
            "acr_score": as_float(data.get("acrScore")),
            "aes_score": as_float(data.get("aesScore")),
            "exposure_score": as_float(data.get("aesScore")),
            "last_seen": data.get("lastSeen"),
            "last_scan": data.get("lastScan") or data.get("lastSeen"),
            "last_scan_id": data.get("lastScanId"),
            "first_seen": data.get("firstSeen"),
            "sources": ["tenable_sc:/rest/asset"],
            "tags": _as_list(data.get("tags")),
            "retrieved": utc_now(),
            "source_ref": f"GET /rest/asset/{asset_uuid}",
        }

    def agent_inventory(self) -> tuple[list[dict[str, Any]] | None, str | None]:
        try:
            payload = _unwrap(self.http.get_json("/rest/agent"))
        except ScopeError as exc:
            return None, f"agent inventory unavailable with this API scope: {exc}"
        except NotFoundError:
            return None, "Security Center agent inventory endpoint is not available"
        except ConnectorError as exc:
            return None, f"agent inventory unavailable: {exc}"
        items = payload if isinstance(payload, list) else payload.get("agents") or []
        agents = []
        for item in items:
            if not isinstance(item, dict):
                continue
            agents.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name") or item.get("hostName"),
                    "platform": item.get("platform"),
                    "version": item.get("version"),
                    "status": item.get("status"),
                    "last_connect": item.get("lastConnect") or item.get("lastSeen"),
                    "linked_on": item.get("linkedOn"),
                    "plugin_feed_id": item.get("pluginFeedId"),
                    "groups": item.get("groups"),
                }
            )
        return agents, None

    # -- parsing -------------------------------------------------------

    @staticmethod
    def _severity(row: dict[str, Any]) -> int | None:
        value = row.get("severity")
        if isinstance(value, dict):
            return as_int(value.get("id"))
        return as_int(value)

    @staticmethod
    def _asset_key(row: dict[str, Any]) -> str:
        return str(
            row.get("assetID")
            or row.get("assetId")
            or row.get("ip")
            or row.get("macAddress")
            or "unknown"
        )

    def _parse_finding(self, row: dict[str, Any]) -> Finding:
        asset_id = self._asset_key(row)
        hostname = (
            _text(row.get("dnsName"))
            or _text(row.get("netbiosName"))
            or _text(row.get("hostName"))
        )
        mac = normalize_mac(_text(row.get("macAddress")))
        asset = AssetRef(
            uuid=asset_id,
            hostname=hostname,
            fqdn=_text(row.get("dnsName")),
            netbios=_text(row.get("netbiosName")),
            ipv4=_text(row.get("ip")),
            mac=mac,
            os=_split_csv(row.get("os") or row.get("operatingSystem")),
            agent_uuid=None,
            last_seen=row.get("lastSeen"),
        )
        return Finding(
            plugin_id=as_int(row.get("pluginID") or row.get("pluginId")) or 0,
            plugin_name=_text(row.get("pluginName")) or "unknown plugin",
            family=_text(row.get("pluginFamily")) or "unknown",
            severity=self._severity(row),
            asset=asset,
            source="tenable_sc",
            cvss3_base=as_float(row.get("cvssV3BaseScore")),
            cvss2_base=as_float(row.get("cvssBaseScore")),
            cvss3_vector=_text(row.get("cvssV3Vector")),
            cvss2_vector=_text(row.get("cvssVector")),
            vpr=as_float(row.get("vprScore")),
            cve=_split_csv(row.get("cve")),
            cpe=_split_csv(row.get("cpe")),
            exploit_available=as_bool(row.get("exploitAvailable")),
            exploited_by_malware=as_bool(row.get("exploitedByMalware")),
            in_the_news=as_bool(row.get("inTheNews")),
            has_patch=as_bool(row.get("patchAvailable")),
            patch_publication_date=row.get("patchPubDate"),
            solution=truncate(_text(row.get("solution")) or "", 4000),
            synopsis=truncate(_text(row.get("synopsis")) or "", 2000),
            description=truncate(_text(row.get("description")) or "", 6000),
            port=as_int(row.get("port")),
            protocol=_text(row.get("protocol")),
            output=truncate(_text(row.get("pluginText")) or "", 8000),
            first_found=row.get("firstSeen"),
            last_found=row.get("lastSeen"),
            state=_text(row.get("state")),
        )

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "Tenable Security Center",
            "base_url": self.settings.base_url,
            "user_agent": self.settings.user_agent,
            "profile": self.settings.profile,
            "live": True,
            "live_validated": False,
            "credential_configured": True,
            "limitations": [
                "Security Center adapter follows the documented /rest API but was "
                "not exercised against a live SC appliance in this environment.",
                "SC column names vary by version; unmapped fields degrade to unknown.",
            ],
        }


__all__ = ["TenableSCClient", "_unwrap"]
