from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|client_secret)\b\s*[:=]\s*([^\s&;,'\"]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[a-z0-9._\-~+/]+=*")
_SECRET_QUERY_PARAM = re.compile(r"(?i)([?&](?:token|api[_-]?key|password|secret)=)[^&#\s]+")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DEPTH_PLACEHOLDER = "[MAX_DEPTH_EXCEEDED]"
_CONTEXT_PLACEHOLDER = "[CONTEXT_TRUNCATED]"
_HUGE_BLOB_PLACEHOLDER = "[HUGE_BLOB_STRIPPED]"
_DEFAULT_BINARY_PLACEHOLDER = "[BINARY_DATA_STRIPPED]"


@dataclass(frozen=True)
class PromptSanitizerConfig:
    max_text_chars: int = 1000
    max_context_chars: int = 20_000
    max_json_depth: int = 6
    max_list_items: int = 50
    binary_placeholder: str = _DEFAULT_BINARY_PLACEHOLDER


@dataclass
class PromptSanitizerMetadata:
    truncated: int = 0
    redacted: int = 0
    stripped_controls: int = 0
    binary_stripped: int = 0
    huge_blobs_stripped: int = 0
    depth_limited: int = 0
    dropped_items: int = 0
    total_chars: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "truncated": self.truncated,
            "redacted": self.redacted,
            "stripped_controls": self.stripped_controls,
            "binary_stripped": self.binary_stripped,
            "huge_blobs_stripped": self.huge_blobs_stripped,
            "depth_limited": self.depth_limited,
            "dropped_items": self.dropped_items,
            "total_chars": self.total_chars,
        }


@dataclass(frozen=True)
class SanitizedPayload:
    value: Any
    metadata: PromptSanitizerMetadata


class PromptSanitizer:
    """Pure sanitizer for data crossing into AI prompt/provider context."""

    def __init__(self, config: PromptSanitizerConfig | None = None) -> None:
        self.config = config or PromptSanitizerConfig()

    def sanitize(self, value: Any) -> SanitizedPayload:
        metadata = PromptSanitizerMetadata()
        copied = copy.deepcopy(value)
        sanitized = self._sanitize(copied, depth=0, metadata=metadata)
        return SanitizedPayload(value=sanitized, metadata=metadata)

    def clean_text(self, value: Any, max_chars: int | None = None) -> str:
        metadata = PromptSanitizerMetadata()
        return self._clean_text(str(value), max_chars or self.config.max_text_chars, metadata)

    def clean_optional_text(self, value: Any, max_chars: int | None = None) -> str | None:
        if value is None:
            return None
        return self.clean_text(value, max_chars=max_chars)

    def _sanitize(self, value: Any, *, depth: int, metadata: PromptSanitizerMetadata) -> Any:
        if depth > self.config.max_json_depth:
            metadata.depth_limited += 1
            return self._apply_context_budget(_DEPTH_PLACEHOLDER, metadata)

        if isinstance(value, bytes | bytearray | memoryview):
            metadata.binary_stripped += 1
            return self._apply_context_budget(self.config.binary_placeholder, metadata)

        if isinstance(value, str):
            return self._clean_text(value, self.config.max_text_chars, metadata)

        if isinstance(value, list | tuple | set):
            items = list(value)
            if len(items) > self.config.max_list_items:
                metadata.dropped_items += len(items) - self.config.max_list_items
            return [self._sanitize(item, depth=depth + 1, metadata=metadata) for item in items[: self.config.max_list_items]]

        if isinstance(value, dict):
            entries = list(value.items())
            if len(entries) > self.config.max_list_items:
                metadata.dropped_items += len(entries) - self.config.max_list_items
            sanitized: dict[str, Any] = {}
            for key, item in entries[: self.config.max_list_items]:
                clean_key = self._clean_text(str(key), 128, metadata)
                sanitized[clean_key] = self._sanitize(item, depth=depth + 1, metadata=metadata)
            return sanitized

        return value

    def _clean_text(self, value: str, max_chars: int, metadata: PromptSanitizerMetadata) -> str:
        control_count = len(_CONTROL_CHARS.findall(value))
        if control_count:
            metadata.stripped_controls += control_count
        text = _CONTROL_CHARS.sub("", value)

        if "�" in text:
            metadata.binary_stripped += 1
            return self._apply_context_budget(self.config.binary_placeholder, metadata)

        if len(text) > max_chars * 8:
            metadata.huge_blobs_stripped += 1
            return self._apply_context_budget(_HUGE_BLOB_PLACEHOLDER, metadata)

        text, count = _SECRET_ASSIGNMENT.subn(lambda match: f"{match.group(1)}=[REDACTED]", text)
        metadata.redacted += count
        text, count = _BEARER_TOKEN.subn("Bearer [REDACTED]", text)
        metadata.redacted += count
        text, count = _SECRET_QUERY_PARAM.subn(lambda match: f"{match.group(1)}[REDACTED]", text)
        metadata.redacted += count

        if len(text) > max_chars:
            suffix = "...[truncated]"
            text = text[: max(0, max_chars - len(suffix))] + suffix
            metadata.truncated += 1

        return self._apply_context_budget(text, metadata)

    def _apply_context_budget(self, text: str, metadata: PromptSanitizerMetadata) -> str:
        remaining = self.config.max_context_chars - metadata.total_chars
        if remaining <= 0:
            metadata.truncated += 1
            return _CONTEXT_PLACEHOLDER
        if len(text) > remaining:
            suffix = "...[context-truncated]"
            text = text[: max(0, remaining - len(suffix))] + suffix
            metadata.truncated += 1
        metadata.total_chars += len(text)
        return text
