"""Shared HTTP download: explicit timeouts, project User-Agent and retries.

Only the standard library is used. Nothing in this module logs HTTP headers:
log lines carry the URL without query string, the attempt number, the status
code, the wait and the error type.
"""

from __future__ import annotations

import http.client
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from typing import Any
from urllib.parse import urlsplit, urlunsplit

log = logging.getLogger(__name__)

REPO_URL = "https://github.com/NicolaGarciaE/threat-intel-pipeline"
USER_AGENT = f"threat-intel-pipeline/{version('threat-intel-pipeline')} (+{REPO_URL})"

SOCKET_TIMEOUT_S = 30  # connect and each read
ATTEMPT_DEADLINE_S = 120  # whole body of one attempt
MAX_BYTES = 100_000_000  # 100 MB; KEV was 1,807,090 and EPSS 2,775,639 in session 0
CHUNK_SIZE = 64 * 1024

MAX_ATTEMPTS = 4
BACKOFF_BASE_S = 10  # waits after failed attempts 1, 2, 3: 10 s, 30 s, 90 s
BACKOFF_FACTOR = 3
RETRY_AFTER_CAP_S = 120


class DownloadError(Exception):
    """The download failed for good: non-retryable answer or retries exhausted."""


class _RetryableError(Exception):
    """A failure worth another attempt: network error, 429 or 5xx."""

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True)
class FetchResult:
    url: str
    final_url: str
    content: bytes
    downloaded_at: datetime  # UTC, when the body was fully received
    attempts: int


def redact(url: str) -> str:
    """URL safe to log: scheme, host, port and path only."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def fetch(
    url: str,
    *,
    opener: Any = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> FetchResult:
    """GET ``url`` following redirects and return the body as bytes.

    Retries network errors, 429 and 5xx up to ``MAX_ATTEMPTS`` attempts in
    total, waiting longer each time. Any other non-200 answer fails at once.
    ``opener``, ``sleep`` and ``clock`` are injectable so tests need no network
    and no real waiting.
    """
    opener = opener or urllib.request.build_opener()
    safe_url = redact(url)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        started = clock()
        try:
            final_url, content = _attempt(opener, url, clock, started)
        except _RetryableError as exc:
            if attempt == MAX_ATTEMPTS:
                raise DownloadError(
                    f"GET {safe_url} failed after {MAX_ATTEMPTS} attempts; last error: {exc}"
                ) from exc
            wait = _wait_seconds(attempt, exc.retry_after)
            log.warning(
                "GET %s attempt %d/%d failed: %s; retrying in %d s",
                safe_url, attempt, MAX_ATTEMPTS, exc, wait,
            )
            sleep(wait)
            continue
        except DownloadError as exc:
            raise DownloadError(f"GET {safe_url} failed: {exc}") from exc

        log.info(
            "GET %s -> 200, %s bytes in %.1f s (attempt %d/%d)",
            safe_url, f"{len(content):,}", clock() - started, attempt, MAX_ATTEMPTS,
        )
        if final_url != url:
            log.info("GET %s was redirected to %s", safe_url, redact(final_url))
        return FetchResult(
            url=url,
            final_url=final_url,
            content=content,
            downloaded_at=datetime.now(UTC),
            attempts=attempt,
        )
    raise AssertionError("unreachable")  # the loop always returns or raises


def _attempt(opener: Any, url: str, clock: Callable[[], float], started: float) -> tuple[str, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=SOCKET_TIMEOUT_S) as response:
            if response.status != 200:
                raise DownloadError(f"HTTP {response.status}, expected 200")
            final_url = response.geturl()
            if urlsplit(final_url).scheme != "https":
                raise DownloadError(f"final URL is not https: {redact(final_url)}")
            declared = _declared_length(response)
            if declared is not None and declared > MAX_BYTES:
                raise DownloadError(f"response larger than {MAX_BYTES:,} bytes")
            content = _read_body(response, clock, started)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 429 or 500 <= exc.code <= 599:
            retry_after = _retry_after(exc) if exc.code in (429, 503) else None
            raise _RetryableError(f"HTTP {exc.code}", retry_after) from exc
        raise DownloadError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        # URLError covers DNS and refused connections; OSError covers resets
        # and socket timeouts; HTTPException covers broken HTTP responses.
        raise _RetryableError(f"{type(exc).__name__}: {exc}") from exc

    if declared is not None and len(content) != declared:
        raise _RetryableError(
            f"incomplete body: received {len(content):,} bytes, Content-Length differs"
        )
    return final_url, content


def _read_body(response: Any, clock: Callable[[], float], started: float) -> bytes:
    chunks: list[bytes] = []
    received = 0
    while True:
        if clock() - started > ATTEMPT_DEADLINE_S:
            raise _RetryableError(f"attempt took longer than {ATTEMPT_DEADLINE_S} s")
        chunk = response.read(CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        received += len(chunk)
        if received > MAX_BYTES:
            raise DownloadError(f"response larger than {MAX_BYTES:,} bytes")
        chunks.append(chunk)


def _declared_length(response: Any) -> int | None:
    return _non_negative_int(response.headers.get("Content-Length"))


def _retry_after(exc: urllib.error.HTTPError) -> int | None:
    """``Retry-After`` in whole seconds; HTTP-date values are ignored."""
    if exc.headers is None:
        return None
    return _non_negative_int(exc.headers.get("Retry-After"))


def _non_negative_int(value: str | None) -> int | None:
    if value is None:
        return None
    value = value.strip()
    if not (value.isascii() and value.isdigit()):
        return None
    return int(value)


def _wait_seconds(attempt: int, retry_after: int | None) -> int:
    wait = BACKOFF_BASE_S * BACKOFF_FACTOR ** (attempt - 1)
    if retry_after is not None:
        wait = max(wait, min(retry_after, RETRY_AFTER_CAP_S))
    return wait
