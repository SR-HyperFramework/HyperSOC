"""Import an exported JSONL file through signed ingest or authenticated inventory.

Use a log shipper to POST native envelopes for continuous collection. This CLI
replays exports, resumes from an atomic checkpoint, and never logs credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


def signed_headers(secret: str, content: bytes) -> dict:
    observed = str(int(time.time()))
    signature = hmac.new(secret.encode(), observed.encode() + b"." + content, hashlib.sha256).hexdigest()
    return {"Content-Type": "application/json", "X-SOC-Timestamp": observed, "X-SOC-Signature": signature}


async def replay(args):
    source = Path(args.file).resolve(strict=True)
    checkpoint = Path(args.checkpoint).resolve() if args.checkpoint else source.with_suffix(source.suffix + ".soc-checkpoint")
    if checkpoint == source:
        raise ValueError("Checkpoint must not overwrite the input file")
    if args.format != "inventory" and not os.environ.get("SOC_INGEST_SECRET"):
        raise ValueError("SOC_INGEST_SECRET is required for signed events")
    if args.format == "inventory" and not os.environ.get("SOC_CONNECTOR_TOKEN"):
        raise ValueError("SOC_CONNECTOR_TOKEN needs an admin bearer session for inventory imports")
    parsed = urlsplit(args.url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Supply a base HTTP(S) URL without credentials, query, or fragment")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"} and not args.allow_local_http:
        raise ValueError("Remote connectors require HTTPS; --allow-local-http is for an isolated network")
    with source.open("rb") as digest_stream:
        content_digest = hashlib.file_digest(digest_stream, "sha256").hexdigest()
    start = 0
    if checkpoint.exists():
        saved = json.loads(checkpoint.read_text(encoding="utf-8"))
        if saved.get("digest") != content_digest:
            raise ValueError("Input changed; use a new checkpoint to replay safely")
        start = int(saved["line"])
    endpoint = {"inventory": "/api/v1/hub/inventory", "canonical": "/api/v1/hub/events"}.get(args.format, "/api/v1/hub/native-events")
    accepted = 0
    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
        with source.open(encoding="utf-8-sig") as stream:
            for line_number, line in enumerate(stream, 1):
                if line_number <= start or not line.strip():
                    continue
                if len(line.encode()) > 1_048_576:
                    raise ValueError(f"Input line {line_number} exceeds the ingest size limit")
                payload = json.loads(line)
                if args.format not in {"canonical", "inventory"}:
                    payload = {"format": args.format, "source": args.source, "event": payload, **({"category": args.category} if args.category else {})}
                body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
                headers = {"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["SOC_CONNECTOR_TOKEN"]} if args.format == "inventory" else signed_headers(os.environ["SOC_INGEST_SECRET"], body)
                # 429/5xx retry uses a fresh timestamp; retries retain native event IDs.
                for attempt in range(5):
                    if args.format != "inventory":
                        headers = signed_headers(os.environ["SOC_INGEST_SECRET"], body)
                    response = await client.post(args.url.rstrip("/") + endpoint, content=body, headers=headers)
                    if response.status_code not in {429, 500, 502, 503, 504}:
                        break
                    await asyncio.sleep(min(16, 2**attempt))
                if response.status_code not in {200, 201}:
                    raise ValueError(f"Input line {line_number} rejected with HTTP {response.status_code}; checkpoint retained")
                checkpoint.parent.mkdir(parents=True, exist_ok=True)
                temporary = checkpoint.with_suffix(checkpoint.suffix + ".tmp")
                temporary.write_text(json.dumps({"digest": content_digest, "line": line_number}), encoding="utf-8")
                temporary.replace(checkpoint)
                accepted += 1
    return accepted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--format", choices=["ecs", "osquery", "wazuh", "canonical", "inventory"], required=True)
    parser.add_argument("--source", default="external-export", help="Stable source namespace, such as edr-prod or cmdb")
    parser.add_argument("--category", choices=["detection", "behavior", "posture"])
    parser.add_argument("--checkpoint")
    parser.add_argument("--allow-local-http", action="store_true")
    args = parser.parse_args()
    try:
        count = asyncio.run(replay(args))
    except (ValueError, OSError, httpx.HTTPError) as exc:
        # API bodies, file content and httpx exception URLs may contain secrets.
        parser.exit(1, f"Connector stopped ({type(exc).__name__}); inspect the checkpoint and input contract.\n")
    print(f"Imported {count} JSONL records; checkpoint saved.")


if __name__ == "__main__":
    main()
