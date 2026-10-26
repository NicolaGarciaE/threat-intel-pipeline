"""Shared download: timeout, User-Agent, retries and no headers in logs. No network."""

import http.client
import io
import logging
import urllib.error

import pytest
from helpers import NetworkAccessBlocked

from threat_intel_pipeline.ingest import download
from threat_intel_pipeline.ingest.download import USER_AGENT, DownloadError, fetch, redact

URL = "https://example.test/file.json"
CANARY = "CANARY-HEADER-VALUE-7f3a"


def make_headers(**fields: str) -> http.client.HTTPMessage:
    headers = http.client.HTTPMessage()
    headers["X-Canary"] = CANARY
    for name, value in fields.items():
        headers[name.replace("_", "-")] = value
    return headers


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, final_url: str = URL, content_length: str | None = "auto"):
        self.status = status
        self._body = io.BytesIO(body)
        self._final_url = final_url
        length = str(len(body)) if content_length == "auto" else content_length
        self.headers = make_headers(**({"Content_Length": length} if length is not None else {}))

    def geturl(self) -> str:
        return self._final_url

    def read(self, size: int) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def http_error(code: int, **fields: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, code, "message", make_headers(**fields), io.BytesIO(b""))


class FakeOpener:
    def __init__(self, outcomes: list) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0
        self.user_agents: list[str | None] = []
        self.timeouts: list[float] = []

    def open(self, request, timeout):
        self.calls += 1
        self.user_agents.append(request.get_header("User-agent"))
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def run_fetch(outcomes: list):
    opener = FakeOpener(outcomes)
    sleeps: list[float] = []
    result = fetch(URL, opener=opener, sleep=sleeps.append)
    return result, opener, sleeps


def run_failing_fetch(outcomes: list, match: str):
    opener = FakeOpener(outcomes)
    sleeps: list[float] = []
    with pytest.raises(DownloadError, match=match):
        fetch(URL, opener=opener, sleep=sleeps.append)
    return opener, sleeps


def test_first_attempt_ok_sends_user_agent_and_explicit_timeout():
    result, opener, sleeps = run_fetch([FakeResponse(b"hello")])
    assert result.content == b"hello"
    assert result.attempts == 1
    assert sleeps == []
    assert opener.user_agents == [USER_AGENT]
    assert USER_AGENT.startswith("threat-intel-pipeline/")
    assert opener.timeouts == [30]


def test_5xx_is_retried_with_growing_waits():
    result, opener, sleeps = run_fetch([http_error(503), http_error(503), FakeResponse(b"ok")])
    assert result.attempts == 3
    assert sleeps == [10, 30]


def test_404_is_not_retried():
    opener, sleeps = run_failing_fetch([http_error(404)], match="HTTP 404")
    assert opener.calls == 1
    assert sleeps == []


def test_gives_up_after_4_network_errors():
    opener, sleeps = run_failing_fetch(
        [urllib.error.URLError("boom")] * 4, match="failed after 4 attempts; last error: URLError"
    )
    assert opener.calls == 4
    assert sleeps == [10, 30, 90]


def test_socket_timeout_is_retried():
    result, opener, sleeps = run_fetch([TimeoutError("timed out"), FakeResponse(b"x")])
    assert result.attempts == 2
    assert sleeps == [10]


@pytest.mark.parametrize(
    ("code", "retry_after", "expected_wait"),
    [
        (429, "100", 100),  # honoured when longer than the planned wait
        (429, "500", 120),  # capped at 120 s
        (503, "Wed, 21 Oct 2026 07:28:00 GMT", 10),  # HTTP-date ignored: planned wait
    ],
)
def test_retry_after(code, retry_after, expected_wait):
    _, _, sleeps = run_fetch([http_error(code, Retry_After=retry_after), FakeResponse(b"x")])
    assert sleeps == [expected_wait]


def test_incomplete_body_is_retried():
    result, _, sleeps = run_fetch([FakeResponse(b"abc", content_length="10"), FakeResponse(b"abc")])
    assert result.attempts == 2
    assert sleeps == [10]


def test_non_https_final_url_fails_without_retry():
    opener, _ = run_failing_fetch([FakeResponse(b"x", final_url="http://example.test/file.json")], match="not https")
    assert opener.calls == 1


def test_success_status_other_than_200_fails_without_retry():
    opener, _ = run_failing_fetch([FakeResponse(b"x", status=206)], match="HTTP 206, expected 200")
    assert opener.calls == 1


def test_final_url_after_redirect_is_recorded():
    result, _, _ = run_fetch([FakeResponse(b"x", final_url="https://example.test/file-2026-10-26.json")])
    assert result.url == URL
    assert result.final_url == "https://example.test/file-2026-10-26.json"


@pytest.mark.parametrize("content_length", ["auto", None], ids=["declared", "streamed"])
def test_body_over_max_bytes_fails_without_retry(monkeypatch, content_length):
    monkeypatch.setattr(download, "MAX_BYTES", 10)
    opener, _ = run_failing_fetch([FakeResponse(b"x" * 20, content_length=content_length)], match="larger than 10")
    assert opener.calls == 1


def test_logs_never_contain_headers(caplog):
    caplog.set_level(logging.DEBUG)
    run_fetch([FakeResponse(b"x")])
    run_fetch([http_error(503, Retry_After="5"), FakeResponse(b"x", final_url="https://example.test/other")])
    run_failing_fetch([http_error(403)], match="HTTP 403")
    assert "GET https://example.test/file.json" in caplog.text
    assert CANARY not in caplog.text
    assert "X-Canary" not in caplog.text
    assert "Retry-After" not in caplog.text


def test_redact_keeps_only_scheme_host_and_path():
    assert redact("https://user:secret@example.test:8443/a/b.csv?key=SECRET#x") == "https://example.test:8443/a/b.csv"


def test_network_guard_blocks_real_requests():
    """conftest.py makes any real connection fail at once, without retries."""

    def no_sleep(seconds: float) -> None:
        pytest.fail("a blocked connection must not be retried")

    with pytest.raises(NetworkAccessBlocked):
        fetch("https://www.cisa.gov/", sleep=no_sleep)
