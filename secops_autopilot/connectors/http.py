"""Shared HTTP transport for Tenable APIs.

Every request carries the integration User-Agent Tenable requires, plus the
``X-ApiKeys`` header. Retries distinguish transient failures (429/5xx) from
authorization and scope failures, which must be surfaced rather than retried.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Callable

import requests

from ..errors import (
    AuthError,
    ConflictError,
    ConnectorError,
    NotFoundError,
    RateLimitError,
    ScopeError,
)
from ..util import utc_now

LOGGER = logging.getLogger("secops.tenable")

RETRYABLE_STATUS = {500, 502, 503, 504}


class TenableHTTP:
    def __init__(
        self,
        *,
        base_url: str,
        access_key: str,
        secret_key: str,
        user_agent: str,
        timeout: int = 60,
        max_retries: int = 4,
        verify_tls: bool = True,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.verify_tls = verify_tls
        self._sleep = sleep
        self.calls: list[dict[str, Any]] = []
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key};",
                "User-Agent": user_agent,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip, deflate",
            }
        )

    # -- public API -----------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        allow_status: set[int] | None = None,
        timeout: int | None = None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        allow_status = allow_status or set()
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            started = time.monotonic()
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    timeout=(10, timeout or self.timeout),
                    verify=self.verify_tls,
                )
            except requests.RequestException as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    raise ConnectorError(f"{method} {path} failed: {exc}") from exc
                self._backoff(attempt)
                continue
            elapsed_ms = int((time.monotonic() - started) * 1000)
            self._record(method, path, params, response.status_code, elapsed_ms)
            status = response.status_code
            if status in allow_status:
                return response
            if 200 <= status < 300:
                return response
            if status == 401:
                raise AuthError(
                    f"Tenable rejected the API key for {method} {path} (HTTP 401). "
                    "Check the access/secret key pair and the account's API access."
                )
            if status == 403:
                message = self._body_message(response)
                if "scope" in message.lower():
                    raise ScopeError(
                        f"Tenable credential lacks scope for {method} {path} "
                        f"(HTTP 403): {message}"
                    )
                raise AuthError(
                    f"Tenable denied {method} {path} (HTTP 403): {message}"
                )
            if status == 404:
                raise NotFoundError(f"{method} {path} returned HTTP 404")
            if status == 409:
                raise ConflictError(
                    f"{method} {path} conflict (HTTP 409): {self._body_message(response)}",
                    payload=self._json_or_empty(response),
                )
            if status == 429:
                retry_after = self._retry_after(response)
                last_error = RateLimitError(
                    f"{method} {path} was rate limited (HTTP 429)",
                    retry_after=retry_after,
                )
                if attempt >= self.max_retries:
                    raise last_error
                self._sleep(min(retry_after, 60.0))
                continue
            if status in RETRYABLE_STATUS and attempt < self.max_retries:
                last_error = ConnectorError(
                    f"{method} {path} returned HTTP {status}"
                )
                self._backoff(attempt)
                continue
            raise ConnectorError(
                f"{method} {path} returned HTTP {status}: {self._body_message(response)}"
            )
        raise ConnectorError(f"{method} {path} failed after retries: {last_error}")

    def get_json(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        allow_status: set[int] | None = None,
        timeout: int | None = None,
    ) -> Any:
        response = self.request(
            "GET",
            path,
            params=params,
            allow_status=allow_status,
            timeout=timeout,
        )
        return self._json(response, path)

    def post_json(
        self,
        path: str,
        body: dict[str, Any],
        *,
        params: dict[str, Any] | None = None,
        allow_status: set[int] | None = None,
        timeout: int | None = None,
    ) -> Any:
        response = self.request(
            "POST",
            path,
            params=params,
            json_body=body,
            allow_status=allow_status,
            timeout=timeout,
        )
        return self._json(response, path)

    def public_call_log(self) -> list[dict[str, Any]]:
        return list(self.calls)

    # -- internals ------------------------------------------------------

    def _json(self, response: requests.Response, path: str) -> Any:
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise ConnectorError(
                f"{path} returned non-JSON content ({response.headers.get('Content-Type')})"
            ) from exc

    def _record(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        status: int,
        elapsed_ms: int,
    ) -> None:
        entry = {
            "at": utc_now(),
            "method": method,
            "path": path,
            "status": status,
            "duration_ms": elapsed_ms,
        }
        if params:
            # Query values never contain credentials; they are filter values.
            entry["query"] = {
                key: value for key, value in params.items() if key.startswith(("filter", "limit", "date_range", "offset"))
            }
        self.calls.append(entry)
        if len(self.calls) > 500:
            del self.calls[:100]
        LOGGER.debug("%s %s -> %s (%dms)", method, path, status, elapsed_ms)

    @staticmethod
    def _body_message(response: requests.Response) -> str:
        try:
            payload = response.json()
        except ValueError:
            return (response.text or "").strip()[:400]
        if isinstance(payload, dict):
            for key in ("message", "error", "detail"):
                value = payload.get(key)
                if value:
                    return str(value)[:400]
        return str(payload)[:400]

    @staticmethod
    def _json_or_empty(response: requests.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError:
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _retry_after(response: requests.Response) -> float:
        raw = response.headers.get("Retry-After", "1")
        try:
            return max(0.0, float(raw))
        except ValueError:
            return 1.0

    def _backoff(self, attempt: int) -> None:
        delay = min(2**attempt, 20) + random.uniform(0.0, 0.5)
        self._sleep(delay)
