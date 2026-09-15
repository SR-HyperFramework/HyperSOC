from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from app.schemas.normalized_alert import NormalizedAlert

IndicatorTypeName = Literal["ip", "domain", "hash", "url"]
VALID_INDICATOR_TYPES: tuple[IndicatorTypeName, ...] = ("ip", "domain", "hash", "url")

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_URL_LENGTH = 2048


class InvalidIndicatorError(ValueError):
    """Raised when a caller asks to enrich a malformed IOC."""


@dataclass(frozen=True)
class ExtractedIndicator:
    type: IndicatorTypeName
    value: str
    evidence_path: str


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    text = str(value).strip()
    return text or None


def _canonical_ip(value: Any) -> str:
    text = _text(value)
    if text is None:
        raise InvalidIndicatorError("ip indicator is required")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise InvalidIndicatorError("ip indicator must be a valid IP address") from exc


def _canonical_hash(value: Any) -> str:
    text = _text(value)
    if text is None:
        raise InvalidIndicatorError("hash indicator is required")
    candidate = text.upper()
    if not _HASH_RE.fullmatch(candidate):
        raise InvalidIndicatorError("hash indicator must be MD5, SHA1, or SHA256 hex")
    return candidate


def _canonical_domain(value: Any, *, allow_ip: bool = False) -> str:
    text = _text(value)
    if text is None:
        raise InvalidIndicatorError("domain indicator is required")
    candidate = text.rstrip(".").casefold()
    if not candidate or len(candidate) > 253:
        raise InvalidIndicatorError("domain indicator must be 1-253 characters")

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        if allow_ip:
            return candidate
        raise InvalidIndicatorError("domain indicator must not be an IP address")

    try:
        ascii_domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidIndicatorError("domain indicator must be IDNA-compatible") from exc

    labels = ascii_domain.split(".")
    if any(not label or not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise InvalidIndicatorError("domain indicator contains an invalid label")
    if len(ascii_domain) > 253:
        raise InvalidIndicatorError("domain indicator must be 1-253 characters")
    return ascii_domain


def _canonical_url_host(hostname: str) -> str:
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return _canonical_domain(hostname)


def _canonical_url(value: Any) -> str:
    text = _text(value)
    if text is None:
        raise InvalidIndicatorError("url indicator is required")
    if len(text) > _MAX_URL_LENGTH:
        raise InvalidIndicatorError("url indicator is too long")

    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidIndicatorError("url indicator must use http or https")
    if not parts.hostname:
        raise InvalidIndicatorError("url indicator must include a host")

    host = _canonical_url_host(parts.hostname)
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidIndicatorError("url indicator has an invalid port") from exc

    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"

    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    if len(normalized) > _MAX_URL_LENGTH:
        raise InvalidIndicatorError("url indicator is too long")
    return normalized


def canonicalize_indicator(indicator_type: str, value: Any) -> str:
    if indicator_type == "ip":
        return _canonical_ip(value)
    if indicator_type == "domain":
        return _canonical_domain(value)
    if indicator_type == "hash":
        return _canonical_hash(value)
    if indicator_type == "url":
        return _canonical_url(value)
    raise InvalidIndicatorError("indicator type must be ip, domain, hash, or url")


def maybe_canonicalize_indicator(indicator_type: IndicatorTypeName, value: Any) -> str | None:
    try:
        return canonicalize_indicator(indicator_type, value)
    except InvalidIndicatorError:
        return None


def domain_from_url(value: Any) -> str | None:
    try:
        normalized = _canonical_url(value)
    except InvalidIndicatorError:
        return None
    hostname = urlsplit(normalized).hostname
    if hostname is None:
        return None
    return maybe_canonicalize_indicator("domain", hostname)


def _append_indicator(
    results: list[ExtractedIndicator],
    seen: set[tuple[IndicatorTypeName, str, str]],
    indicator_type: IndicatorTypeName,
    value: Any,
    evidence_path: str,
) -> None:
    canonical = maybe_canonicalize_indicator(indicator_type, value)
    if canonical is None:
        return
    key = (indicator_type, canonical, evidence_path)
    if key in seen:
        return
    seen.add(key)
    results.append(ExtractedIndicator(type=indicator_type, value=canonical, evidence_path=evidence_path))


def extract_indicators(alert: NormalizedAlert) -> list[ExtractedIndicator]:
    """Extract bounded IOCs from canonical Phase 4 fields only."""
    results: list[ExtractedIndicator] = []
    seen: set[tuple[IndicatorTypeName, str, str]] = set()

    _append_indicator(results, seen, "ip", alert.network.src_ip, "network.src_ip")
    _append_indicator(results, seen, "ip", alert.network.dst_ip, "network.dst_ip")
    _append_indicator(results, seen, "ip", alert.host.ip, "host.ip")

    _append_indicator(results, seen, "domain", alert.network.domain, "network.domain")
    _append_indicator(results, seen, "domain", alert.network.dns_query, "network.dns_query")

    url = maybe_canonicalize_indicator("url", alert.network.url)
    if url is not None:
        _append_indicator(results, seen, "url", url, "network.url")
        _append_indicator(results, seen, "domain", domain_from_url(url), "network.url.host")

    _append_indicator(results, seen, "hash", alert.file.hash, "file.hash")
    _append_indicator(results, seen, "hash", alert.process.hash, "process.hash")

    return results
