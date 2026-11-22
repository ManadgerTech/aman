"""Aman (أمان) - a self-hosted privacy gateway for LLM APIs.

Sits between your application and any OpenAI-compatible endpoint (OpenAI,
Ollama, vLLM, ...). Before a request leaves your machine, Aman replaces
personal data it detects - emails, cards, API keys, Moroccan identifiers
(CIN, ICE, phone numbers, MA IBANs) and Arabic/French person names - with
stable placeholders. It restores the original values in the response,
including streamed responses, before your application sees them.

Stdlib only. No data ever leaves except to the upstream you configure.
The audit log records redaction counts by type, never the values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "0.1.0"

PLACEHOLDER_PREFIX = "__AMAN_PII_"
MAX_PLACEHOLDER_LEN = 32  # generous bound for streaming carry


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _regex_spans(pattern: "re.Pattern[str]", text: str, kind: str) -> List[Span]:
    return [Span(m.start(), m.end(), kind) for m in pattern.finditer(text)]


def _group_spans(pattern: "re.Pattern[str]", text: str, kind: str,
                 group: int = 1) -> List[Span]:
    """Spans over a capturing group (e.g. the name after an honorific)."""
    return [Span(m.start(group), m.end(group), kind)
            for m in pattern.finditer(text)]


_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_API_KEY_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|"
    r"xox[baprs]-[0-9A-Za-z-]{10,}|ya29\.[0-9A-Za-z_-]{20,})\b"
)
# Moroccan identifiers
_CIN_RE = re.compile(r"\b[A-Z]{1,2}\d{5,6}\b")  # e.g. AB123456
_PHONE_MA_RE = re.compile(r"(?<!\w)(?:\+212|00212|0)\s?[67](?:[\s.\-]?\d{2}){4}\b")
_IBAN_MA_RE = re.compile(r"\bMA\d{26}\b")
_ICE_RE = re.compile(r"\b\d{15}\b")
_ICE_HINT_RE = re.compile(r"(?:ICE|RC/ICE|آيسي)", re.IGNORECASE)

# Person names via honorifics and self-introductions.
# Person names: the keyword (honorific / self-introduction) stays visible,
# only the name is redacted. Arabic letters only (no punctuation), at most
# two tokens for Arabic names to avoid swallowing the following verb.
# Handles the ligature spelling للسيد (article alef dropped) as well as
# السيد / للأستاذ / الدكتور forms.
_AR_NAME = r"[ء-ي]{2,}(?:\s+[ء-ي]{2,})?"
_AR_HONORIFIC_RE = re.compile(
    r"(?:ا?ل{1,2}ا?(?:سيد|سيدة|حاج|حاجة|مهندس|مهندسة)"
    r"|ا?ل{1,2}(?:أستاذ|أستاذة|دكتور|دكتورة))"
    rf"\s+({_AR_NAME})"
)
_AR_SELF_RE = re.compile(rf"(?:اسمي|سميتي)\s+({_AR_NAME})")
_FR_NAME = r"[A-ZÀ-Ý][\wà-ÿ-]+(?:\s+[A-ZÀ-Ý][\wà-ÿ-]+){0,2}"
_FR_HONORIFIC_RE = re.compile(
    rf"\b(?:M\.|Mme|Mlle|Dr|Me)\s+({_FR_NAME})"
)
_FR_SELF_RE = re.compile(
    rf"[Jj]e m'appelle\s+({_FR_NAME})"
)


def detect_spans(text: str, enabled: Optional[Sequence[str]] = None) -> List[Span]:
    """Find all PII spans in *text*. ``enabled`` limits detector kinds."""
    spans: List[Span] = []
    want = set(enabled) if enabled else None

    def add(kind: str, found: Iterable[Span]) -> None:
        if want is None or kind in want:
            spans.extend(found)

    add("EMAIL", _regex_spans(_EMAIL_RE, text, "EMAIL"))

    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if digits.isdigit() and _luhn_ok(digits):
            add("CARD", [Span(m.start(), m.end(), "CARD")])

    add("API_KEY", _regex_spans(_API_KEY_RE, text, "API_KEY"))
    add("IBAN_MA", _regex_spans(_IBAN_MA_RE, text, "IBAN_MA"))
    add("PHONE_MA", _regex_spans(_PHONE_MA_RE, text, "PHONE_MA"))

    for m in _CIN_RE.finditer(text):
        token = m.group(0)
        # Avoid clashing with API keys already matched and all-same-letter
        # false friends; CIN is letters followed by digits only.
        if re.fullmatch(r"[A-Z]{1,2}\d{5,6}", token):
            add("CIN_MA", [Span(m.start(), m.end(), "CIN_MA")])

    for m in _ICE_RE.finditer(text):
        window = text[max(0, m.start() - 40): m.start()]
        if _ICE_HINT_RE.search(window):
            add("ICE_MA", [Span(m.start(), m.end(), "ICE_MA")])

    add("PERSON", _group_spans(_AR_HONORIFIC_RE, text, "PERSON"))
    add("PERSON", _group_spans(_AR_SELF_RE, text, "PERSON"))
    add("PERSON", _group_spans(_FR_HONORIFIC_RE, text, "PERSON"))
    add("PERSON", _group_spans(_FR_SELF_RE, text, "PERSON"))

    return _dedupe(spans)


def _dedupe(spans: List[Span]) -> List[Span]:
    """Resolve overlaps, longest first; drop contained duplicates."""
    ordered = sorted(spans, key=lambda s: (-(s.end - s.start), s.start))
    kept: List[Span] = []
    for span in ordered:
        if any(not (span.end <= k.start or span.start >= k.end) for k in kept):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: s.start)


# ---------------------------------------------------------------------------
# Redaction / restoration
# ---------------------------------------------------------------------------


@dataclass
class Redaction:
    clean_text: str
    mapping: Dict[str, str]  # placeholder -> original value


class Redactor:
    """Stateless redactor: redact() then restore() with the same mapping."""

    def redact(self, text: str, enabled: Optional[Sequence[str]] = None) -> Redaction:
        spans = detect_spans(text, enabled)
        mapping: Dict[str, str] = {}
        counters: Dict[str, int] = {}
        out: List[str] = []
        cursor = 0
        for span in spans:
            counters[span.kind] = counters.get(span.kind, 0) + 1
            placeholder = f"{PLACEHOLDER_PREFIX}{span.kind}_{counters[span.kind]}__"
            out.append(text[cursor:span.start])
            out.append(placeholder)
            mapping[placeholder] = text[span.start:span.end]
            cursor = span.end
        out.append(text[cursor:])
        return Redaction(clean_text="".join(out), mapping=mapping)

    @staticmethod
    def restore(text: str, mapping: Dict[str, str]) -> str:
        for placeholder, original in mapping.items():
            text = text.replace(placeholder, original)
        return text


def _placeholder_kind(placeholder: str) -> str:
    """Extract the detector kind from a placeholder string."""
    core = placeholder[len(PLACEHOLDER_PREFIX):].rstrip("_")
    return core.rsplit("_", 1)[0]


class StreamingRestorer:
    """Restore placeholders inside a token stream.

    A placeholder can be split across chunks (e.g. "__AMAN_PI" + "I_EMAIL_1__").
    feed() returns only text that cannot still become a placeholder; flush()
    emits whatever remains at end of stream.
    """

    def __init__(self, mapping: Dict[str, str]):
        self._mapping = mapping
        self._carry = ""

    def feed(self, chunk: str) -> str:
        buf = self._carry + chunk
        idx = buf.rfind(PLACEHOLDER_PREFIX)
        if idx != -1:
            if len(buf) - idx > MAX_PLACEHOLDER_LEN:
                # Too long to still be a placeholder: emit everything.
                emit, self._carry = buf, ""
            else:
                emit, self._carry = buf[:idx], buf[idx:]
        else:
            # Hold back a suffix that could be the start of a placeholder.
            hold = 0
            for k in range(min(len(buf), len(PLACEHOLDER_PREFIX) - 1), 0, -1):
                if buf.endswith(PLACEHOLDER_PREFIX[:k]):
                    hold = k
                    break
            emit = buf[: len(buf) - hold]
            self._carry = buf[len(buf) - hold:]
        return Redactor.restore(emit, self._mapping)

    def flush(self) -> str:
        emit, self._carry = self._carry, ""
        return Redactor.restore(emit, self._mapping)


# ---------------------------------------------------------------------------
# Audit log: counts by type, never values
# ---------------------------------------------------------------------------


class AuditLog:
    def __init__(self, path: Optional[str]):
        self._path = path
        self._lock = threading.Lock()

    def record(self, endpoint: str, mapping: Dict[str, str]) -> None:
        if not self._path or not mapping:
            return
        counts: Dict[str, int] = {}
        for placeholder in mapping:
            kind = _placeholder_kind(placeholder)
            counts[kind] = counts.get(kind, 0) + 1
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "endpoint": endpoint,
            "redacted": counts,
        }
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Request/response transformation (OpenAI-compatible)
# ---------------------------------------------------------------------------


def redact_messages(messages: list, redactor: Redactor) -> Tuple[list, Dict[str, str]]:
    """Redact every message content. Returns (messages, merged mapping)."""
    merged: Dict[str, str] = {}
    out = []
    for msg in messages:
        msg = dict(msg)
        content = msg.get("content")
        if isinstance(content, str):
            r = redactor.redact(content)
            msg["content"] = r.clean_text
            merged.update(r.mapping)
        elif isinstance(content, list):  # multimodal parts
            parts = []
            for part in content:
                part = dict(part)
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    r = redactor.redact(part["text"])
                    part["text"] = r.clean_text
                    merged.update(r.mapping)
                parts.append(part)
            msg["content"] = parts
        out.append(msg)
    return out, merged


def restore_response_body(body: dict, mapping: Dict[str, str]) -> dict:
    for choice in body.get("choices", []):
        message = choice.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            message["content"] = Redactor.restore(message["content"], mapping)
        if isinstance(choice.get("text"), str):
            choice["text"] = Redactor.restore(choice["text"], mapping)
    return body


def restore_sse_line(line: str, restorer: StreamingRestorer) -> str:
    """Restore one SSE line; non-data lines pass through unchanged."""
    if not line.startswith("data:") or line.strip() == "data: [DONE]":
        return line
    try:
        payload = json.loads(line[5:].strip())
    except json.JSONDecodeError:
        return line
    for choice in payload.get("choices", []):
        delta = choice.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("content"), str):
            delta["content"] = restorer.feed(delta["content"])
        if isinstance(choice.get("text"), str):
            choice["text"] = restorer.feed(choice["text"])
    return "data: " + json.dumps(payload, ensure_ascii=False)


# ---------------------------------------------------------------------------
# HTTP proxy server
# ---------------------------------------------------------------------------


class _ProxyHandler(BaseHTTPRequestHandler):
    upstream: str = "http://localhost:11434/v1"
    redactor: Redactor = Redactor()
    audit: AuditLog = AuditLog(None)
    timeout: float = 300.0
    server_version = f"Aman/{__version__}"

    def log_message(self, fmt: str, *args) -> None:  # quiet by default
        pass

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "upstream": self.upstream,
                                  "version": __version__})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.rstrip("/").endswith(("chat/completions", "completions")):
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid JSON body"})
            return

        mapping: Dict[str, str] = {}
        if isinstance(body.get("messages"), list):
            body["messages"], mapping = redact_messages(body["messages"], self.redactor)
        if isinstance(body.get("prompt"), str):
            r = self.redactor.redact(body["prompt"])
            body["prompt"] = r.clean_text
            mapping.update(r.mapping)
        self.audit.record(self.path, mapping)

        headers = {"Content-Type": "application/json"}
        auth = self.headers.get("Authorization")
        if auth:
            headers["Authorization"] = auth
        req = urllib.request.Request(
            self.upstream.rstrip("/") + self.path,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            upstream_resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            self._send_json(exc.code, {"error": f"upstream error: {exc.code}"})
            return
        except OSError as exc:
            self._send_json(502, {"error": f"upstream unreachable: {exc}"})
            return

        if body.get("stream"):
            self._relay_stream(upstream_resp, mapping)
        else:
            data = json.loads(upstream_resp.read().decode("utf-8"))
            data = restore_response_body(data, mapping)
            self._send_json(upstream_resp.status, data)

    def _relay_stream(self, upstream_resp, mapping: Dict[str, str]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        restorer = StreamingRestorer(mapping)
        buf = b""
        while True:
            chunk = upstream_resp.read(1024)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                raw_line, buf = buf.split(b"\n", 1)
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r")
                if line:
                    self.wfile.write(
                        (restore_sse_line(line, restorer) + "\n").encode("utf-8"))
                else:
                    self.wfile.write(b"\n")
            self.wfile.flush()
        tail = restorer.flush()
        if tail:
            # Placeholder tail that never completed; emit it restored.
            self.wfile.write(tail.encode("utf-8"))
        self.wfile.flush()


def serve(upstream: str, host: str, port: int, audit_path: Optional[str],
          timeout: float = 300.0) -> None:
    handler = type("BoundHandler", (_ProxyHandler,), {
        "upstream": upstream,
        "audit": AuditLog(audit_path),
        "timeout": timeout,
    })
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Aman {__version__} listening on http://{host}:{port}", file=sys.stderr)
    print(f"Upstream: {upstream}", file=sys.stderr)
    if audit_path:
        print(f"Audit log (counts only, never values): {audit_path}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_scan(text: str, show_originals: bool) -> int:
    redactor = Redactor()
    result = redactor.redact(text)
    print(result.clean_text)
    if result.mapping:
        print("\nRedactions:", file=sys.stderr)
        for placeholder, original in result.mapping.items():
            kind = _placeholder_kind(placeholder)
            shown = original if show_originals else f"<{len(original)} chars>"
            print(f"  {kind}: {placeholder} -> {shown}", file=sys.stderr)
    else:
        print("\nNo PII detected.", file=sys.stderr)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aman",
        description="Self-hosted privacy gateway for LLM APIs.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="Run the proxy server")
    p_serve.add_argument("--upstream",
                         default=os.environ.get("AMAN_UPSTREAM",
                                                "http://localhost:11434/v1"),
                         help="OpenAI-compatible upstream base URL")
    p_serve.add_argument("--host", default=os.environ.get("AMAN_HOST", "127.0.0.1"))
    p_serve.add_argument("--port", type=int,
                         default=int(os.environ.get("AMAN_PORT", "8787")))
    p_serve.add_argument("--audit", default=os.environ.get("AMAN_AUDIT"),
                         help="Path to audit log (counts only, never values)")
    p_serve.add_argument("--timeout", type=float, default=300.0)

    p_scan = sub.add_parser("scan", help="Redact text and print the result")
    p_scan.add_argument("text", nargs="?", help="Text (default: stdin)")
    p_scan.add_argument("--show-originals", action="store_true",
                        help="Print detected values (default: lengths only)")

    args = parser.parse_args(argv)

    if args.command == "serve":
        serve(upstream=args.upstream, host=args.host, port=args.port,
              audit_path=args.audit, timeout=args.timeout)
        return 0
    if args.command == "scan":
        text = args.text if args.text is not None else sys.stdin.read()
        return _cmd_scan(text, show_originals=args.show_originals)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
