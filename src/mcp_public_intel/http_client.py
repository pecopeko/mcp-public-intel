"""Shared SSRF-safe HTTP client, polite rate limiting, safe XML parsing, and HTML converters."""

from __future__ import annotations

import email.utils
import html
import ipaddress
import re
import socket
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    import httpx

from mcp_public_intel import __version__

DEFAULT_USER_AGENT = (
    f"MCPPublicIntel/{__version__} (+https://github.com/pecopeko/mcp-public-intel)"
)
DEFAULT_SEC_USER_AGENT = f"MCPPublicIntel/{__version__} (contact@mcp-public-intel.dev)"
SEC_MAX_REQUESTS_PER_SECOND = 8.0

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RETRY_STATUSES = frozenset({429, 503})
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_FORBIDDEN_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
    }
)
_FORBIDDEN_HOST_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa")
_CDATA_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_UNSAFE_DTD_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_XML_ENCODING_RE = re.compile(
    r"^\s*<\?xml[^>]*encoding\s*=\s*[\"']([A-Za-z0-9._-]+)[\"']",
    re.IGNORECASE,
)


class SSRFError(ValueError):
    """Raised when a URL fails public-network SSRF safety validation."""


def build_sec_user_agent(contact_email: str | None = None) -> str:
    """Build a SEC EDGAR Fair-Access-compliant User-Agent header."""
    cleaned = str(contact_email or "").strip()
    if cleaned and _EMAIL_RE.match(cleaned):
        return f"MCPPublicIntel/{__version__} ({cleaned})"
    return DEFAULT_SEC_USER_AGENT


def is_public_ip(addr: str) -> bool:
    """Return True strictly for globally routable public IPv4/IPv6 addresses."""
    ip_obj = ipaddress.ip_address(addr.split("%")[0])
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(
        ip_obj.is_global
        and not ip_obj.is_private
        and not ip_obj.is_loopback
        and not ip_obj.is_link_local
        and not ip_obj.is_multicast
        and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )


def _default_resolve_host(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return [str(info[4][0]) for info in infos if info and len(info) >= 5 and info[4]]


def assert_safe_public_url(
    raw_url: str,
    *,
    preserve_path: bool = True,
    resolve_host_fn: Callable[[str, int], list[str]] | None = None,
) -> str:
    """Validate an HTTP(S) URL and block localhost, private, loopback, link-local, or metadata IPs."""
    cleaned = str(raw_url or "").strip()
    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.netloc:
        raise SSRFError(f"Unsupported or invalid HTTP(S) URL: {raw_url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFError(f"Credentials in URL are disallowed: {raw_url!r}")

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if (
        not host
        or host in _FORBIDDEN_HOSTS
        or any(host.endswith(suffix) for suffix in _FORBIDDEN_HOST_SUFFIXES)
    ):
        raise SSRFError(f"Forbidden local or internal host: {host!r}")

    is_literal_ip = False
    try:
        ip_obj = ipaddress.ip_address(host)
        is_literal_ip = True
        if not is_public_ip(str(ip_obj)):
            raise SSRFError(f"Forbidden non-public IP: {host}")
    except SSRFError:
        raise
    except ValueError:
        pass

    if not is_literal_ip:
        port = parsed.port or (443 if scheme == "https" else 80)
        resolver = resolve_host_fn if resolve_host_fn is not None else _default_resolve_host
        for addr in resolver(host, port):
            if not is_public_ip(addr):
                raise SSRFError(f"Host {host!r} resolved to non-public IP {addr}")

    if preserve_path:
        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{parsed.netloc}{path}{query}"
    return f"{scheme}://{parsed.netloc}"


class RateLimiter:
    """Polite monotonic-clock rate limiter for public APIs like SEC EDGAR."""

    def __init__(
        self,
        max_per_second: float = SEC_MAX_REQUESTS_PER_SECOND,
        *,
        sleep_fn: Callable[[float], None] = time.sleep,
        clock_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_per_second = max(0.1, float(max_per_second))
        self.min_interval = 1.0 / self.max_per_second
        self._sleep = sleep_fn
        self._clock = clock_fn
        self._last_ts: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._last_ts is not None:
            remaining = self.min_interval - (now - self._last_ts)
            if remaining > 0:
                self._sleep(remaining)
                now = self._clock()
        self._last_ts = now


def parse_retry_after(header_value: str | None, max_backoff: float) -> float | None:
    """Parse HTTP Retry-After header (seconds or HTTP-date) capped at max_backoff."""
    if not header_value:
        return None
    text = header_value.strip()
    if not text:
        return None
    try:
        return max(0.0, min(float(text), max_backoff))
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, min(delta, max_backoff))
    except (TypeError, ValueError):
        return None


def safe_http_get(
    client: httpx.Client,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    max_redirects: int = 4,
    max_retries: int = 3,
    base_backoff: float = 0.75,
    max_backoff: float = 10.0,
    rate_limiter: RateLimiter | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    resolve_host_fn: Callable[[str, int], list[str]] | None = None,
) -> httpx.Response:
    """Perform SSRF-validated GET with redirect hop checks and 429/503 Retry-After backoff."""
    current_url = assert_safe_public_url(
        url, preserve_path=True, resolve_host_fn=resolve_host_fn
    )
    current_params = dict(params) if params else None

    for hop in range(max_redirects + 1):
        resp: httpx.Response | None = None
        for attempt in range(max_retries + 1):
            if rate_limiter is not None:
                rate_limiter.wait()
            resp = client.get(
                current_url,
                params=current_params,
                headers=headers,
                follow_redirects=False,
            )
            if resp.status_code in _RETRY_STATUSES and attempt < max_retries:
                retry_after = parse_retry_after(resp.headers.get("Retry-After"), max_backoff)
                delay = (
                    retry_after
                    if retry_after is not None
                    else min(max_backoff, base_backoff * (2**attempt))
                )
                if delay > 0:
                    sleep_fn(delay)
                continue
            break

        assert resp is not None
        if resp.status_code in _REDIRECT_STATUSES:
            location = (resp.headers.get("location") or "").strip()
            if not location:
                return resp
            if hop >= max_redirects:
                raise ValueError(f"Exceeded maximum redirects ({max_redirects}) for {url}")
            next_url = urljoin(current_url, location)
            validated_next = assert_safe_public_url(
                next_url, preserve_path=True, resolve_host_fn=resolve_host_fn
            )
            prev_parsed = urlparse(current_url)
            next_parsed = urlparse(validated_next)
            if next_parsed.query or next_parsed.path != prev_parsed.path:
                current_params = None
            current_url = validated_next
            continue

        return resp

    raise ValueError(f"Exceeded maximum redirects ({max_redirects}) for {url}")


def decode_xml_bytes(xml_payload: str | bytes) -> str:
    """Decode XML bytes respecting declared XML encoding while stripping UTF-8 BOM."""
    if isinstance(xml_payload, str):
        return xml_payload.lstrip("\ufeff")
    head = xml_payload[:256].decode("ascii", errors="ignore")
    enc_match = _XML_ENCODING_RE.search(head)
    encoding = enc_match.group(1) if enc_match else "utf-8"
    try:
        text = xml_payload.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        text = xml_payload.decode("utf-8", errors="replace")
    return text.lstrip("\ufeff")


def parse_xml_safely(xml_payload: str | bytes) -> ET.Element:
    """Parse XML strictly rejecting DTD and ENTITY declarations (XXE / billion-laughs guard)."""
    xml_text = decode_xml_bytes(xml_payload)
    stripped_no_cdata = _CDATA_RE.sub("", xml_text)
    if _UNSAFE_DTD_RE.search(stripped_no_cdata):
        raise ValueError("Unsafe XML rejected: DTD and ENTITY declarations are disallowed.")
    return ET.fromstring(xml_text)


class _HTMLTextExtractor(HTMLParser):
    """Lightweight stdlib HTML-to-plain-text converter preserving paragraph separation."""

    _BREAK_TAGS = frozenset({"br", "hr", "li", "tr"})
    _BLOCK_TAGS = frozenset(
        {"p", "div", "section", "article", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "pre"}
    )
    _SKIP_TAGS = frozenset({"script", "style", "svg", "noscript", "button", "form"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.lower()
        if lower in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if lower in self._BREAK_TAGS or lower in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lower = tag.lower()
        if lower in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if not self._skip_depth and lower in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth and data:
            self._parts.append(data)

    def get_text(self) -> str:
        joined = "".join(self._parts).replace("\xa0", " ")
        lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in joined.splitlines()]
        cleaned = "\n".join(lines)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()


class _HTMLMarkdownConverter(HTMLParser):
    """Lightweight stdlib HTML-to-Markdown converter for clean LLM/RAG ingestion."""

    _SKIP_TAGS = frozenset({"script", "style", "svg", "noscript", "button", "form"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0
        self._link_href_stack: list[str | None] = []
        self._in_pre = False
        self._in_blockquote = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.lower()
        if lower in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if lower in ("h1", "h2", "h3", "h4", "h5", "h6"):
            hashes = "#" * int(lower[1])
            self._parts.append(f"\n\n{hashes} ")
        elif lower == "p":
            self._parts.append("\n\n")
            if self._in_blockquote:
                self._parts.append("> ")
        elif lower == "br":
            self._parts.append("\n")
        elif lower == "hr":
            self._parts.append("\n\n---\n\n")
        elif lower == "li":
            self._parts.append("\n- ")
        elif lower == "blockquote":
            self._in_blockquote = True
            self._parts.append("\n\n> ")
        elif lower in ("strong", "b"):
            self._parts.append("**")
        elif lower in ("em", "i"):
            self._parts.append("*")
        elif lower == "pre":
            self._in_pre = True
            self._parts.append("\n\n```\n")
        elif lower == "code" and not self._in_pre:
            self._parts.append("`")
        elif lower == "a":
            href = attr_map.get("href", "").strip()
            self._link_href_stack.append(href or None)
            if href:
                self._parts.append("[")

    def handle_endtag(self, tag: str) -> None:
        lower = tag.lower()
        if lower in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return

        if lower in ("h1", "h2", "h3", "h4", "h5", "h6", "p"):
            self._parts.append("\n\n")
        elif lower == "blockquote":
            self._in_blockquote = False
            self._parts.append("\n\n")
        elif lower in ("strong", "b"):
            self._parts.append("**")
        elif lower in ("em", "i"):
            self._parts.append("*")
        elif lower == "pre":
            self._in_pre = False
            self._parts.append("\n```\n\n")
        elif lower == "code" and not self._in_pre:
            self._parts.append("`")
        elif lower == "a" and self._link_href_stack:
            href = self._link_href_stack.pop()
            if href:
                self._parts.append(f"]({href})")

    def handle_data(self, data: str) -> None:
        if self._skip_depth or not data:
            return
        if self._in_pre:
            self._parts.append(data)
        else:
            cleaned = re.sub(r"[ \t\r\n]+", " ", data.replace("\xa0", " "))
            self._parts.append(cleaned)

    def get_markdown(self) -> str:
        raw = "".join(self._parts)
        lines = [ln.rstrip() for ln in raw.splitlines()]
        joined = "\n".join(lines)
        joined = re.sub(r"\n{3,}", "\n\n", joined)
        return html.unescape(joined).strip()


def html_to_plain_text(raw_html: str | None) -> str:
    """Convert HTML fragment into clean plain text."""
    if not raw_html:
        return ""
    parser = _HTMLTextExtractor()
    parser.feed(str(raw_html))
    parser.close()
    return html.unescape(parser.get_text())


def html_to_markdown(raw_html: str | None) -> str:
    """Convert HTML fragment into clean Markdown."""
    if not raw_html:
        return ""
    parser = _HTMLMarkdownConverter()
    parser.feed(str(raw_html))
    parser.close()
    return parser.get_markdown()
