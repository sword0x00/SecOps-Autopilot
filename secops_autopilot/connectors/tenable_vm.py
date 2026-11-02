"""Tenable Vulnerability Management (cloud.tenable.com) adapter.

Live endpoints used:

* ``GET  /session``                                  — credential check
* ``GET  /workbenches/vulnerabilities``              — CVE -> plugin mapping
* ``POST /vulns/export`` + status/chunks             — per-asset findings
* ``GET  /assets/{uuid}``                            — asset/ACR/AES/agent flags
* ``GET  /scanners/agents``                          — agent inventory (scope-permitting)

Tenable requires a descriptive User-Agent on every request; it is set in the
shared transport and repeated in the evidence snapshot.
"""

from __future__ import annotations

import logging
import random
import re
import time
from collections.abc import Callable
from typing import Any

from ..config import TenableVMSettings
from ..errors import ConflictError, ConnectorError, ExportError, NotFoundError, ScopeError
from ..models import AssetRef, Finding, PluginHit, SourceRef
from ..util import (
    as_bool,
    as_float,
    as_int,
    normalize_mac,
    parse_iso,
    severity_label,
    sha256_obj,
    truncate,
    utc_now,
)
from .http import TenableHTTP

LOGGER = logging.getLogger("secops.tenable.vm")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _vector(value: Any) -> str | None:
    if isinstance(value, dict):
        raw = value.get("raw")
        return str(raw) if raw else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _vpr(value: Any) -> float | None:
    if isinstance(value, dict):
        return as_float(value.get("score") or value.get("vpr_score"))
    return as_float(value)


def _epss(value: Any) -> float | None:
    if isinstance(value, dict):
        return as_float(value.get("score") or value.get("epss_score"))
    return as_float(value)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_str(value: Any) -> str | None:
    for item in _as_list(value):
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None


def _first_mac(value: Any) -> str | None:
    for item in _as_list(value):
        mac = normalize_mac(item if isinstance(item, str) else None)
        if mac:
            return mac
    return None


def _str_list(value: Any) -> list[str]:
    return [str(item) for item in _as_list(value) if item not in (None, "")]


def _normalize_xrefs(value: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            name = item.get("name")
            values = item.get("values")
            if values is None:
                out.append({k: v for k, v in item.items()})
            else:
                for entry in _as_list(values):
                    out.append({"name": name, "value": str(entry)})
        elif item not in (None, ""):
            out.append({"name": None, "value": str(item)})
    return out


def _asset_from_export(raw: dict[str, Any], source: str) -> AssetRef:
    uuid = (
        raw.get("uuid")
        or raw.get("asset_uuid")
        or raw.get("id")
        or f"unidentified-{sha256_obj(raw)[:16]}"
    )
    return AssetRef(
        uuid=str(uuid),
        hostname=_first_str(raw.get("hostname")) or _first_str(raw.get("netbios_name")),
        fqdn=_first_str(raw.get("fqdn")),
        netbios=_first_str(raw.get("netbios_name")),
        ipv4=_first_str(raw.get("ipv4")),
        mac=_first_mac(raw.get("mac_address")),
        os=_str_list(raw.get("operating_system")),
        agent_uuid=raw.get("agent_uuid"),
        last_seen=raw.get("last_seen") or raw.get("last_scan_time"),
        network_id=raw.get("network_id"),
    )


def _port_fields(raw: dict[str, Any]) -> tuple[int | None, str | None, str | None]:
    port = raw.get("port")
    if isinstance(port, dict):
        return (
            as_int(port.get("port")),
            port.get("protocol"),
            port.get("service"),
        )
    if isinstance(port, (int, float, str)):
        return as_int(port), raw.get("protocol"), raw.get("service")
    return None, raw.get("protocol"), raw.get("service")


def finding_from_export(record: dict[str, Any], source: str = "tenable_vm") -> Finding:
    plugin = record.get("plugin") or {}
    port, protocol, service = _port_fields(record)
    scan = record.get("scan") or {}
    severity = as_int(record.get("severity"))
    if severity is None:
        severity = as_int(plugin.get("severity_id"))
    return Finding(
        plugin_id=as_int(plugin.get("id")) or 0,
        plugin_name=str(plugin.get("name") or "unknown plugin"),
        family=str(plugin.get("family") or "unknown"),
        severity=severity,
        asset=_asset_from_export(record.get("asset") or {}, source),
        source=source,
        cvss3_base=as_float(plugin.get("cvss3_base_score")),
        cvss2_base=as_float(plugin.get("cvss_base_score")),
        cvss3_vector=_vector(plugin.get("cvss3_vector")),
        cvss2_vector=_vector(plugin.get("cvss_vector")),
        vpr=_vpr(plugin.get("vpr")) or as_float(plugin.get("vpr_score")),
        epss=_epss(plugin.get("epss_score")),
        cve=_str_list(plugin.get("cve")),
        cpe=_str_list(plugin.get("cpe")),
        xrefs=_normalize_xrefs(plugin.get("xrefs")),
        exploit_available=as_bool(plugin.get("exploit_available")),
        exploited_by_malware=as_bool(plugin.get("exploited_by_malware")),
        exploited_by_nessus=as_bool(plugin.get("exploited_by_nessus")),
        exploit_framework_metasploit=as_bool(plugin.get("exploit_framework_metasploit")),
        in_the_news=as_bool(plugin.get("in_the_news")),
        has_patch=as_bool(plugin.get("has_patch")),
        has_workaround=as_bool(plugin.get("has_workaround")),
        vuln_publication_date=plugin.get("vuln_publication_date"),
        patch_publication_date=plugin.get("patch_publication_date"),
        solution=truncate(plugin.get("solution") or "", 4000),
        synopsis=truncate(plugin.get("synopsis") or "", 2000),
        description=truncate(plugin.get("description") or "", 6000),
        see_also=_str_list(plugin.get("see_also")),
        port=port,
        protocol=protocol,
        service=service,
        output=truncate(record.get("output") or "", 8000),
        first_found=record.get("first_found"),
        last_found=record.get("last_found"),
        state=record.get("state"),
        scan_id=str(scan.get("uuid") or scan.get("id") or "") or None,
    )


class TenableVMClient:
    name = "tenable_vm"
    live = True

    def __init__(
        self,
        settings: TenableVMSettings,
        *,
        export_timeout: int = 300,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not settings.configured:
            raise ConnectorError(
                "Tenable VM credentials are missing; cannot construct the client"
            )
        self.settings = settings
        self.export_timeout = export_timeout
        self._sleep = sleep
        self.http = TenableHTTP(
            base_url=settings.base_url,
            access_key=settings.access_key or "",
            secret_key=settings.secret_key or "",
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_retries=settings.max_retries,
        )
        self.last_workbench: dict[str, Any] = {}
        self.last_exports: list[dict[str, Any]] = []

    # -- health ---------------------------------------------------------

    def health(self) -> dict[str, Any]:
        started = time.monotonic()
        session = self.http.get_json("/session")
        workbench_ok = True
        workbench_error = None
        try:
            self.http.get_json(
                "/workbenches/vulnerabilities",
                params={"date_range": 1, "limit": 1},
            )
        except ConnectorError as exc:
            workbench_ok = False
            workbench_error = str(exc)
        agents, agent_reason = self.agent_inventory()
        latency_ms = int((time.monotonic() - started) * 1000)
        return {
            "ok": True,
            "product": "Tenable Vulnerability Management",
            "base_url": self.settings.base_url,
            "account": session.get("username") or session.get("user_name"),
            "permissions_count": len(session.get("user_permissions") or []),
            "workbench_read": workbench_ok,
            "workbench_error": workbench_error,
            "agent_inventory": "available" if agents is not None else "unknown",
            "agent_inventory_reason": agent_reason,
            "user_agent": self.settings.user_agent,
            "latency_ms": latency_ms,
            "retrieved": utc_now(),
        }

    def tenant_summary(self, date_range: int = 90, limit: int = 5000) -> dict[str, Any]:
        """Small tenant overview used by ``secops inventory``."""
        assets_data = self.http.get_json(
            "/workbenches/assets",
            params={"date_range": date_range, "limit": limit},
        )
        vulns_data = self.http.get_json(
            "/workbenches/vulnerabilities",
            params={"date_range": date_range, "limit": limit},
        )
        assets = assets_data.get("assets") or []
        vulns = vulns_data.get("vulnerabilities") or []
        severity_counts: dict[str, int] = {}
        for vuln in vulns:
            label = severity_label(as_int(vuln.get("severity")))
            severity_counts[label] = severity_counts.get(label, 0) + 1
        agents, agent_reason = self.agent_inventory()
        top = sorted(
            vulns,
            key=lambda item: (
                -(as_int(item.get("severity")) or 0),
                -(as_int(item.get("count")) or 0),
            ),
        )[:10]
        return {
            "product": "Tenable Vulnerability Management",
            "base_url": self.settings.base_url,
            "date_range_days": date_range,
            "assets_returned": len(assets),
            "assets_with_agent_flag": sum(1 for asset in assets if asset.get("has_agent") is True),
            "asset_limit": limit,
            "vulnerabilities_returned": len(vulns),
            "severity_distribution": severity_counts,
            "agent_inventory_available": agents is not None,
            "agent_inventory_reason": agent_reason,
            "top_plugins": [
                {
                    "plugin_id": item.get("plugin_id"),
                    "name": item.get("plugin_name"),
                    "severity": severity_label(as_int(item.get("severity"))),
                    "asset_count": item.get("count"),
                    "cvss3": item.get("cvss3_base_score"),
                    "vpr": item.get("vpr_score"),
                }
                for item in top
            ],
            "retrieved": utc_now(),
        }

    # -- CVE -> plugin mapping -----------------------------------------

    def cve_plugin_hits(self, cve: str, date_range: int = 90) -> list[PluginHit]:
        if not CVE_RE.match(cve):
            raise ConnectorError(f"not a CVE identifier: {cve!r}")
        params = {
            "date_range": date_range,
            "limit": 5000,
            "filter.0.filter": "plugin.attributes.cve.raw",
            "filter.0.quality": "eq",
            "filter.0.value": cve.upper(),
            "filter.search_type": "and",
        }
        data = self.http.get_json("/workbenches/vulnerabilities", params=params)
        raw_hits = data.get("vulnerabilities") or []
        hits: list[PluginHit] = []
        for item in raw_hits:
            hits.append(
                PluginHit(
                    plugin_id=as_int(item.get("plugin_id")) or 0,
                    plugin_name=str(item.get("plugin_name") or "unknown plugin"),
                    family=str(item.get("plugin_family") or "unknown"),
                    severity=as_int(item.get("severity")),
                    asset_count=as_int(item.get("count")) or 0,
                    finding_count=None,
                    cvss3_base=as_float(item.get("cvss3_base_score")),
                    cvss2_base=as_float(item.get("cvss_base_score")),
                    vpr=as_float(item.get("vpr_score")),
                    state=item.get("vulnerability_state"),
                )
            )
        hits.sort(
            key=lambda h: (
                -(h.severity if h.severity is not None else -1),
                -(h.vpr if h.vpr is not None else -1),
                h.plugin_id,
            )
        )
        self.last_workbench = {
            "query": params,
            "returned_plugins": len(hits),
            "reported_total_vulnerabilities": data.get("total_vulnerability_count"),
            "reported_total_assets": data.get("total_asset_count"),
            "retrieved": utc_now(),
        }
        return hits

    # -- per-asset findings --------------------------------------------

    def findings_for_plugins(
        self, plugin_ids: list[int], date_range: int = 90
    ) -> list[Finding]:
        ids = sorted({int(pid) for pid in plugin_ids if int(pid) > 0})
        if not ids:
            return []
        findings: list[Finding] = []
        for chunk in [ids[i : i + 50] for i in range(0, len(ids), 50)]:
            records = self._export_plugin_chunk(chunk)
            for record in records:
                finding = finding_from_export(record)
                if finding.state and finding.state.upper() in {"FIXED", "CLOSED"}:
                    continue
                if not self._within_range(finding.last_found, date_range):
                    continue
                findings.append(finding)
        return self._dedupe(findings)

    def _export_plugin_chunk(self, plugin_ids: list[int]) -> list[dict[str, Any]]:
        body = {"filters": {"plugin_id": plugin_ids}, "num_assets": 5000}
        created: dict[str, Any] | None = None
        for attempt in range(3):
            try:
                created = self.http.post_json("/vulns/export", body)
                break
            except ConflictError as exc:
                active = str(exc.payload.get("active_job_id") or "")
                if not active:
                    raise
                LOGGER.info(
                    "Tenable has an active export (%s); waiting for it before retrying",
                    active,
                )
                self._wait_export(active, collect=False)
                self._sleep(1 + random.uniform(0, 1))
        if created is None:
            raise ExportError(
                "could not create a Tenable export after waiting for the active job"
            )
        export_uuid = created.get("export_uuid")
        if not export_uuid:
            raise ExportError(f"Tenable export creation returned no export_uuid: {created}")
        records, meta = self._wait_export(export_uuid, collect=True)
        meta["plugin_ids"] = plugin_ids
        meta["records"] = len(records)
        self.last_exports.append(meta)
        return records

    def _wait_export(
        self, export_uuid: str, *, collect: bool
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        started = time.monotonic()
        seen_chunks: set[int] = set()
        records: list[dict[str, Any]] = []
        history: list[dict[str, Any]] = []
        last_status: dict[str, Any] = {}
        while time.monotonic() - started < self.export_timeout:
            try:
                status = self.http.get_json(f"/vulns/export/{export_uuid}/status")
            except NotFoundError:
                self._sleep(2)
                continue
            last_status = status
            state = status.get("status")
            if not history or history[-1].get("status") != state:
                history.append(
                    {
                        "at": utc_now(),
                        "status": state,
                        "total_chunks": status.get("total_chunks"),
                        "chunks_available": status.get("chunks_available"),
                    }
                )
            available = status.get("chunks_available") or []
            total = as_int(status.get("total_chunks")) or 0
            if collect:
                for chunk in available:
                    chunk_int = as_int(chunk)
                    if chunk_int is None or chunk_int in seen_chunks:
                        continue
                    try:
                        payload = self.http.get_json(
                            f"/vulns/export/{export_uuid}/chunks/{chunk_int}"
                        )
                    except NotFoundError:
                        continue
                    seen_chunks.add(chunk_int)
                    if isinstance(payload, list):
                        records.extend(payload)
                    elif isinstance(payload, dict):
                        records.extend(payload.get("vulnerabilities") or [])
            if state in {"ERROR", "CANCELLED"}:
                raise ExportError(
                    f"Tenable export {export_uuid} ended with {state}: "
                    f"{status.get('failure_reason') or 'no reason supplied'}"
                )
            if state == "FINISHED":
                if total == 0:
                    break
                if collect and len(seen_chunks) >= total:
                    break
                if not collect:
                    break
            self._sleep(2)
        else:
            raise ExportError(
                f"Tenable export {export_uuid} did not finish within "
                f"{self.export_timeout}s; last status={last_status.get('status')}"
            )
        meta = {
            "export_uuid": export_uuid,
            "status_history": history,
            "chunks_fetched": sorted(seen_chunks),
            "total_chunks": as_int(last_status.get("total_chunks")),
            "retrieved": utc_now(),
        }
        return records, meta

    # -- assets / agents ------------------------------------------------

    def asset_detail(self, asset_uuid: str) -> dict[str, Any]:
        try:
            data = self.http.get_json(f"/assets/{asset_uuid}")
        except NotFoundError:
            data = self.http.get_json(f"/workbenches/assets/{asset_uuid}/info")
            if isinstance(data, dict) and "info" in data:
                data = data["info"]
        return self._normalize_asset_detail(data)

    def _normalize_asset_detail(self, data: dict[str, Any]) -> dict[str, Any]:
        acr = data.get("acr_score_v3")
        if acr is None:
            acr = data.get("acr_score")
        aes = data.get("aes_score_v3")
        if aes is None:
            aes = data.get("exposure_score")
        return {
            "asset_uuid": data.get("id") or data.get("uuid"),
            "hostname": _first_str(data.get("hostname")) or _first_str(data.get("netbios_name")),
            "fqdn": _str_list(data.get("fqdn")),
            "ipv4": _str_list(data.get("ipv4")),
            "mac": _first_mac(data.get("mac_address")),
            "os": _str_list(data.get("operating_system")),
            "has_agent": as_bool(data.get("has_agent")),
            "agent_name": _first_str(data.get("agent_name")),
            "acr_score": as_float(acr),
            "aes_score": as_float(aes),
            "exposure_score": as_float(data.get("exposure_score")),
            "last_seen": data.get("last_seen"),
            "last_scan": data.get("last_licensed_scan_date") or data.get("last_seen"),
            "last_scan_id": data.get("last_scan_id"),
            "first_seen": data.get("first_seen"),
            "sources": [
                item.get("name")
                for item in _as_list(data.get("sources"))
                if isinstance(item, dict) and item.get("name")
            ],
            "tags": _as_list(data.get("tags")),
            "retrieved": utc_now(),
            "source_ref": f"GET /assets/{data.get('id') or data.get('uuid')}",
        }

    def agent_inventory(self) -> tuple[list[dict[str, Any]] | None, str | None]:
        try:
            data = self.http.get_json("/scanners/agents", params={"limit": 1000})
        except ScopeError as exc:
            return None, f"agent inventory unavailable with this API scope: {exc}"
        except NotFoundError:
            return None, "agent inventory endpoint is not available on this tenant"
        except ConnectorError as exc:
            return None, f"agent inventory unavailable: {exc}"
        agents: list[dict[str, Any]] = []
        for item in data.get("agents") or []:
            agents.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "platform": item.get("platform"),
                    "version": item.get("version"),
                    "status": item.get("status"),
                    "last_connect": item.get("last_connect"),
                    "linked_on": item.get("linked_on"),
                    "plugin_feed_id": item.get("plugin_feed_id"),
                    "groups": item.get("groups"),
                }
            )
        return agents, None

    # -- helpers -------------------------------------------------------

    @staticmethod
    def _within_range(timestamp: str | None, date_range: int) -> bool:
        parsed = parse_iso(timestamp)
        if parsed is None:
            return True
        from datetime import datetime, timezone

        age_days = (datetime.now(timezone.utc) - parsed).total_seconds() / 86400
        return age_days <= date_range + 1

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[Any, ...]] = set()
        for finding in findings:
            key = (
                finding.asset.uuid,
                finding.plugin_id,
                finding.port,
                finding.protocol,
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(finding)
        return out

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "Tenable Vulnerability Management",
            "base_url": self.settings.base_url,
            "user_agent": self.settings.user_agent,
            "profile": self.settings.profile,
            "live": True,
            "credential_configured": True,
            "limitations": [
                "Agent version/signature freshness is unknown when the API key lacks "
                "the agent inventory scope (observed HTTP 403 'Insufficient scope').",
                "Tenable severity is used as a baseline only when CVSS is absent; the "
                "KRI score is computed by this engine, not taken from Tenable.",
            ],
        }


def source_refs_for_vm(client: TenableVMClient) -> list[SourceRef]:
    """Build provenance entries for the reads performed in this run."""
    refs = [
        SourceRef(
            type="tenable_vm",
            ref="/workbenches/vulnerabilities",
            note="CVE -> plugin mapping",
            detail=client.last_workbench,
        )
    ]
    for export in client.last_exports:
        refs.append(
            SourceRef(
                type="tenable_vm",
                ref=f"/vulns/export/{export.get('export_uuid')}",
                note="per-asset findings export",
                detail=export,
            )
        )
    return refs


__all__ = [
    "CVE_RE",
    "TenableVMClient",
    "finding_from_export",
    "severity_label",
]
