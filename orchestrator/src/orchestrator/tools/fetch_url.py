"""Fetch a page the person referred to.

This is the first thing in the service that reaches outward at a target someone else
chose, which makes it the first thing an attacker can aim. Everything defensive here
exists because of that, and none of it existed anywhere in the codebase before —
`gateway_client` and `extraction/llm` both talk to one configured host.

## The guards, and what each is actually for

**Resolve first, then judge the addresses.** A host allow/deny list on the *name* is
worthless: the attacker controls their own DNS, and `internal.evil.com` can resolve to
`127.0.0.1`. So every name is resolved and every returned address is checked against
the ranges that must never be reachable — loopback, private, link-local, unique-local,
multicast, reserved. Link-local matters most in a cloud deployment: `169.254.169.254`
is the instance metadata service, and on a host that has one, SSRF to it is credential
theft rather than an information leak.

**Check every redirect hop.** Redirects are followed manually with
`follow_redirects=False`, because the usual attack is not a private URL — anyone would
notice that — it is a public URL that 302s to one. A guard that validates the first
URL and lets httpx follow the rest validates nothing.

**Cap the body while streaming it.** `Content-Length` is a claim, not a fact. The
response is read in chunks and abandoned the moment it exceeds the cap, so a
hostile or merely enormous endpoint cannot exhaust memory.

**Allow-list the content type.** The point is reference text. An allow-list rather
than a deny-list, because the failure of a deny-list is silent and open-ended.

**TOCTOU is acknowledged, not solved.** Between resolving a name and connecting,
DNS can change — classic rebinding. Pinning the connection to the validated address
means driving the socket ourselves and setting SNI by hand, which is a much larger
change to make for a fetch that is user-initiated. Recorded here as a known gap
rather than left for someone to discover: the practical attack it enables is reaching
an internal host on a machine where the attacker already chose the URL, and the
mitigations above cover the easier versions.

**robots.txt is not consulted, deliberately.** This fetches a single page a person
has just told us they read, on their explicit instruction — it is not a crawler, and
there is no traversal, no scheduling and no bulk. If this ever becomes automated or
discovers its own URLs, that calculation changes and robots must be honoured.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

from ..config import Settings
from .base import ToolResult, ToolSpec

log = logging.getLogger(__name__)

TOOL_ID = "fetch_url"

#: Only these. A URL with any other scheme is not a page.
ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Reference text, and nothing that needs a parser we do not have.
ALLOWED_CONTENT_TYPES = frozenset(
    {
        "text/html",
        "text/plain",
        "text/markdown",
        "application/xhtml+xml",
    }
)

#: Standard web ports only by default. Blocking the rest is most of the value of a
#: port rule: the interesting internal targets -- 6379, 5432, 9200, 8500 -- are all
#: non-standard, and a page on a non-standard port is rare enough to be worth the
#: friction of an explicit setting.
ALLOWED_PORTS = frozenset({80, 443})


def _is_forbidden_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Why this address must not be reached, or ``None`` if it may be.

    Explicit about link-local because that is the cloud metadata service
    (169.254.169.254), where an SSRF is credential theft rather than a leak.
    """
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (cloud instance metadata lives here)"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    return None


def resolve_and_check(host: str, port: int) -> tuple[list[str], str | None]:
    """Resolves ``host`` and checks every address it answers with.

    Every address, not the first: a name that resolves to one public and one private
    address must be refused, because which one gets connected to is not ours to
    decide.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return [], f"cannot resolve {host!r}: {exc}"

    addresses: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return addresses, f"{host!r} resolved to something that is not an address: {raw!r}"
        reason = _is_forbidden_address(ip)
        if reason is not None:
            return addresses, f"{host!r} resolves to a {reason} address ({ip})"
        addresses.append(str(ip))

    if not addresses:
        return [], f"{host!r} resolved to nothing"
    return addresses, None


def check_url(url: str) -> str | None:
    """Everything that can be judged before connecting. ``None`` means acceptable."""
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return f"unparseable URL: {exc}"

    if parsed.scheme not in ALLOWED_SCHEMES:
        return f"scheme {parsed.scheme!r} is not allowed (only http, https)"
    if not parsed.hostname:
        return "URL has no host"

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        return f"port {port} is not allowed (only 80, 443)"

    # A literal address skips DNS but not the range check.
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        reason = _is_forbidden_address(literal)
        return f"address is {reason}" if reason else None

    _, error = resolve_and_check(parsed.hostname, port)
    return error


class _TextExtractor(HTMLParser):
    """HTML to readable text, with the stdlib.

    No BeautifulSoup: this needs tags stripped and script bodies dropped, which is
    forty lines of `HTMLParser`, and a dependency earns its place by doing something
    harder than that. The output feeds an LLM, which tolerates imperfect whitespace
    far better than it tolerates a page of minified JavaScript.
    """

    _SKIP = frozenset({"script", "style", "noscript", "svg", "head"})
    _BREAK = frozenset(
        {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skipping = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self._SKIP:
            self._skipping += 1
        elif tag == "title":
            self._in_title = True
        elif tag in self._BREAK:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP:
            self._skipping = max(0, self._skipping - 1)
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        # Title first, because `<title>` lives inside `<head>` and `<head>` is
        # skipped. Checking the skip flag first swallowed every page title.
        if self._in_title:
            self.title += data
            return
        if self._skipping:
            return
        if data.strip():
            self._parts.append(data)

    def text(self) -> str:
        joined = "".join(self._parts)
        # Collapse runs of whitespace but keep paragraph breaks, which carry the
        # document's structure and are what the default chunker splits on.
        lines = [" ".join(line.split()) for line in joined.splitlines()]
        return "\n".join(line for line in lines if line)


def to_text(body: bytes, content_type: str) -> tuple[str, str]:
    """``(title, text)`` from a fetched body."""
    decoded = body.decode("utf-8", errors="replace")
    if "html" in content_type:
        parser = _TextExtractor()
        parser.feed(decoded)
        return " ".join(parser.title.split()), parser.text()
    return "", "\n".join(" ".join(line.split()) for line in decoded.splitlines() if line.strip())


class FetchUrlTool:
    """Fetches one page, with every guard in the module docstring applied."""

    name = TOOL_ID

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            timeout=settings.fetch_timeout_secs,
            follow_redirects=False,
            headers={
                # Honest about what we are. A page owner reading their logs should be
                # able to tell this apart from a browser and from a crawler.
                "user-agent": "Kleos/0.1 (personal memory layer; user-initiated fetch)",
                "accept": "text/html,application/xhtml+xml,text/plain;q=0.9",
            },
        )

    def close(self) -> None:
        self._client.close()

    def run(self, url: str = "", **_: object) -> ToolResult:
        if not url:
            return ToolResult.failed("no url given")

        current = url
        for hop in range(self._settings.fetch_max_redirects + 1):
            rejection = check_url(current)
            if rejection is not None:
                # Reported with the hop, because "the URL you gave me was fine and
                # the third redirect was not" is a different and more interesting
                # fact than a bad URL.
                where = "url" if hop == 0 else f"redirect {hop}"
                return ToolResult.failed(f"refused {where}: {rejection}")

            try:
                response = self._client.get(current)
            except httpx.HTTPError as exc:
                return ToolResult.failed(f"fetch failed: {exc}")

            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    return ToolResult.failed("redirect without a location header")
                current = str(response.url.join(location))
                response.close()
                continue

            return self._read(response, current, url)

        return ToolResult.failed(
            f"more than {self._settings.fetch_max_redirects} redirects starting at {url}"
        )

    def _read(self, response: httpx.Response, final_url: str, original_url: str) -> ToolResult:
        if response.status_code >= 400:
            response.close()
            return ToolResult.failed(f"{final_url} returned {response.status_code}")

        content_type = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
        if content_type not in ALLOWED_CONTENT_TYPES:
            response.close()
            return ToolResult.failed(
                f"content-type {content_type or 'unset'!r} is not allowed "
                f"(expected one of {', '.join(sorted(ALLOWED_CONTENT_TYPES))})"
            )

        cap = self._settings.fetch_max_bytes
        chunks: list[bytes] = []
        total = 0
        try:
            # Streamed and counted. Content-Length is a claim; this is the fact.
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > cap:
                    response.close()
                    return ToolResult.failed(f"{final_url} exceeded {cap} bytes")
                chunks.append(chunk)
        except httpx.HTTPError as exc:
            return ToolResult.failed(f"read failed: {exc}")
        finally:
            response.close()

        title, text = to_text(b"".join(chunks), content_type)
        if not text.strip():
            return ToolResult.failed(f"{final_url} had no readable text")

        log.info("fetch_url %s -> %d bytes, %d chars of text", final_url, total, len(text))
        return ToolResult(
            ok=True,
            data={
                "url": final_url,
                # Kept when a redirect moved us, because what the person referred to
                # and what was actually read are different facts and provenance
                # should carry both.
                "requested_url": original_url,
                "title": title,
                "text": text,
                "content_type": content_type,
                "byte_len": total,
            },
            digest=f"{final_url} {total}B {len(text)} chars",
        )


SPEC = ToolSpec(
    tool_id=TOOL_ID,
    display_name="Fetch a web page",
    factory=FetchUrlTool,
    description=(
        "Fetch one web page the person referred to and return its readable text. "
        "Refuses private and link-local addresses, non-web ports, oversized bodies "
        "and non-text content."
    ),
    writes_memory=False,
    reaches_network=True,
)
