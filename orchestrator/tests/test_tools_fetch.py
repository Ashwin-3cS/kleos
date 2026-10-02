"""The fetch tool, which is the first thing here that aims at a target someone else chose.

Every guard has a test because every guard exists for a specific attack, and a guard
nobody tested is a guard that works until the day it matters. The network is never
touched: address checks are pure, and the response-handling tests drive a mock
transport so a size cap and a redirect chain can be exercised deterministically.
"""

from __future__ import annotations

import httpx
import pytest

from orchestrator.config import Settings
from orchestrator.tools.base import ToolResult
from orchestrator.tools.fetch_url import (
    ALLOWED_CONTENT_TYPES,
    FetchUrlTool,
    check_url,
    to_text,
)


@pytest.fixture
def settings_for_fetch(settings) -> Settings:
    return settings


# -- what may be reached ------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://127.0.0.1:80/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://10.0.0.5/internal",
        "http://172.16.4.4/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ],
)
def test_addresses_that_must_never_be_reached(url: str) -> None:
    """Link-local is the one that matters most in a cloud deployment:
    169.254.169.254 is the instance metadata service, where an SSRF is credential
    theft rather than an information leak."""
    assert check_url(url) is not None, f"{url} must be refused"


def test_a_public_name_that_resolves_to_loopback_is_refused() -> None:
    """The case a hostname blocklist cannot catch. The attacker controls their own
    DNS, so judging the *name* is worthless -- `127.0.0.1.nip.io` is a perfectly
    ordinary public name that resolves to loopback. Only checking after resolution
    catches it."""
    rejection = check_url("http://127.0.0.1.nip.io/")
    assert rejection is not None
    assert "loopback" in rejection


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://example.com/", "ftp://x/y"])
def test_only_http_and_https(url: str) -> None:
    assert "scheme" in (check_url(url) or "")


@pytest.mark.parametrize("port", [22, 5432, 6379, 8090, 9200, 11211])
def test_non_web_ports_are_refused(port: int) -> None:
    """Most of the value of a port rule: the interesting internal targets are all on
    non-standard ports, and a page served on one is rare enough to be worth the
    friction."""
    assert "port" in (check_url(f"http://example.com:{port}/") or "")


def test_a_url_with_no_host_is_refused() -> None:
    assert check_url("http:///nohost") is not None


def test_an_ordinary_public_url_is_allowed() -> None:
    assert check_url("https://example.com/page") is None


# -- what comes back ----------------------------------------------------


def _tool_with(settings: Settings, handler) -> FetchUrlTool:
    tool = FetchUrlTool(settings)
    tool._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        timeout=5.0,
    )
    return tool


def test_a_page_becomes_text(settings_for_fetch) -> None:
    html = b"<html><head><title>RAG</title><style>p{}</style></head><body>" \
           b"<script>evil()</script><p>Retrieval augmented generation.</p>" \
           b"<p>It combines a retriever with a generator.</p></body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=html, headers={"content-type": "text/html"})

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/rag")
    finally:
        tool.close()

    assert result.ok, result.error
    assert result.data["title"] == "RAG"
    assert "Retrieval augmented generation." in result.data["text"]
    assert "evil()" not in result.data["text"], "script bodies must not reach the model"
    assert "p{}" not in result.data["text"]


def test_an_oversized_body_is_abandoned_mid_stream(settings_for_fetch) -> None:
    """Content-Length is a claim, not a fact, so the cap is enforced while reading.
    A hostile or merely enormous endpoint must not be able to exhaust memory."""
    big = b"<p>" + b"x" * (settings_for_fetch.fetch_max_bytes + 1000) + b"</p>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=big, headers={"content-type": "text/html"})

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/huge")
    finally:
        tool.close()
    assert not result.ok
    assert "exceeded" in (result.error or "")


@pytest.mark.parametrize("content_type", ["application/pdf", "image/png", "application/zip", ""])
def test_content_types_outside_the_allow_list_are_refused(
    settings_for_fetch, content_type: str
) -> None:
    """An allow-list rather than a deny-list, because the failure of a deny-list is
    silent and open-ended."""

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-type": content_type} if content_type else {}
        return httpx.Response(200, content=b"data", headers=headers)

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/thing")
    finally:
        tool.close()
    assert not result.ok
    assert "content-type" in (result.error or "")


def test_every_allowed_content_type_is_text_shaped() -> None:
    assert all(t.startswith(("text/", "application/xhtml")) for t in ALLOWED_CONTENT_TYPES)


def test_a_redirect_to_a_private_address_is_refused(settings_for_fetch) -> None:
    """The attack this guard is actually for. Nobody submits a private URL -- they
    submit a public one that 302s to a private one, which a guard that validates only
    the first URL lets straight through."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/creds"})
        raise AssertionError("the redirect target must never be requested")

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/innocent")
    finally:
        tool.close()
    assert not result.ok
    assert "redirect 1" in (result.error or ""), result.error
    assert "link-local" in (result.error or "")


def test_a_redirect_chain_is_bounded(settings_for_fetch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/again"})

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/start")
    finally:
        tool.close()
    assert not result.ok
    assert "redirects" in (result.error or "")


def test_an_error_status_is_a_failure_not_an_empty_page(settings_for_fetch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"gone", headers={"content-type": "text/html"})

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/missing")
    finally:
        tool.close()
    assert not result.ok and "404" in (result.error or "")


def test_a_page_with_no_readable_text_is_a_failure(settings_for_fetch) -> None:
    """Otherwise it would be handed to the model, which would invent something."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"<html><script>only()</script></html>",
            headers={"content-type": "text/html"},
        )

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/empty")
    finally:
        tool.close()
    assert not result.ok and "readable" in (result.error or "")


def test_the_final_url_and_the_requested_url_are_both_kept(settings_for_fetch) -> None:
    """What the person referred to and what was actually read are different facts, and
    provenance should carry both."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://example.com/final"})
        return httpx.Response(
            200, content=b"<p>arrived</p>", headers={"content-type": "text/html"}
        )

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/start")
    finally:
        tool.close()
    assert result.ok, result.error
    assert result.data["requested_url"].endswith("/start")
    assert result.data["url"].endswith("/final")


def test_no_url_is_a_failure_not_a_crash(settings_for_fetch) -> None:
    tool = FetchUrlTool(settings_for_fetch)
    try:
        assert tool.run().ok is False
    finally:
        tool.close()


def test_a_failure_is_reported_rather_than_raised(settings_for_fetch) -> None:
    """A tool failing is an ordinary outcome -- a page is gone, a host is down -- and
    the caller has to record the attempt either way. Raising would make "tried and
    failed" indistinguishable from "never tried"."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    tool = _tool_with(settings_for_fetch, handler)
    try:
        result = tool.run(url="https://example.com/down")
    finally:
        tool.close()
    assert isinstance(result, ToolResult)
    assert not result.ok and result.error


# -- text extraction ----------------------------------------------------


def test_plain_text_passes_through() -> None:
    title, text = to_text(b"line one\n\nline two", "text/plain")
    assert title == ""
    assert "line one" in text and "line two" in text


def test_paragraph_breaks_survive_html() -> None:
    """They carry the document's structure and are what the default chunker splits
    on, so collapsing them would make every page one chunk."""
    _, text = to_text(b"<p>first</p><p>second</p>", "text/html")
    assert "first" in text and "second" in text
    assert "\n" in text
