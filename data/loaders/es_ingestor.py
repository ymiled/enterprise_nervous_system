"""
Elasticsearch Ingestor
----------------------
Ingests any ENS seed JSON file into the local Elasticsearch index.
Run this once after `docker compose up -d` to populate the logs store.

Usage:
    uv run python data/loaders/es_ingestor.py
    uv run python data/loaders/es_ingestor.py --file data/seeds/log4shell_logs.json
    uv run python data/loaders/es_ingestor.py --url http://localhost:9200 --index ens-logs

The script is idempotent — re-running it with the same file will overwrite
existing documents (matched by their 'id' field) without creating duplicates.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config.settings import ES_INDEX, ES_URL, LOGS_SEED_FILE

_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "service":   {"type": "keyword"},
            "level":     {"type": "keyword"},
            "trace_id":  {"type": "keyword"},
            "logger":    {"type": "keyword"},
            "message":   {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
            "env":        {"type": "keyword"},
            "source_url": {"type": "keyword"},
        }
    }
}


def _ensure_index(client: httpx.Client, url: str, index: str) -> None:
    resp = client.head(f"{url}/{index}")
    if resp.status_code == 404:
        resp = client.put(f"{url}/{index}", json=_MAPPING)
        resp.raise_for_status()
        print(f"  Created index '{index}'")
    else:
        print(f"  Index '{index}' already exists")


def _bulk_index(client: httpx.Client, url: str, index: str, docs: list[dict]) -> int:
    """Send docs via ES _bulk API. Uses doc 'id' field as the document _id."""
    lines = []
    for doc in docs:
        doc_id = doc.get("id", "")
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(doc))

    body = "\n".join(lines) + "\n"
    resp = client.post(
        f"{url}/_bulk",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    resp.raise_for_status()
    result = resp.json()

    errors = [item for item in result.get("items", []) if "error" in item.get("index", {})]
    if errors:
        print(f"  [WARN] {len(errors)} bulk errors:", file=sys.stderr)
        for e in errors[:3]:
            print(f"    {e['index']['error']}", file=sys.stderr)

    indexed = len(result.get("items", [])) - len(errors)
    return indexed


def ingest(file: Path, url: str, index: str) -> None:
    print(f"\nIngesting {file} → {url}/{index}")

    docs = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(docs, list):
        print("[ERROR] Seed file must be a JSON array of log objects.", file=sys.stderr)
        sys.exit(1)

    print(f"  {len(docs)} documents to ingest")

    with httpx.Client(timeout=30) as client:
        # Wait for ES to be ready
        try:
            client.get(f"{url}/_cluster/health").raise_for_status()
        except Exception:
            print(f"[ERROR] Cannot reach Elasticsearch at {url}", file=sys.stderr)
            print("  Run:  docker compose up -d", file=sys.stderr)
            sys.exit(1)

        _ensure_index(client, url, index)
        indexed = _bulk_index(client, url, index, docs)

    print(f"  Done — {indexed}/{len(docs)} documents indexed into '{index}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest ENS seed logs into Elasticsearch")
    parser.add_argument("--file",  type=Path, default=LOGS_SEED_FILE,
                        help="Path to seed JSON file (default: log4shell_logs.json)")
    parser.add_argument("--url",   default=ES_URL,   help="Elasticsearch URL")
    parser.add_argument("--index", default=ES_INDEX, help="Index name")
    args = parser.parse_args()

    ingest(args.file, args.url, args.index)
