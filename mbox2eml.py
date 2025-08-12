#!/usr/bin/env python3
"""
MBOX -> EML (streaming, safe filenames, MIME-decode, 8-byte hash, skip duplicates)

Usage:
  python mbox_to_eml.py -f big.mbox -o outdir
"""
from __future__ import annotations
import argparse
import mailbox
import os
import re
import hashlib
import unicodedata
from pathlib import Path
from typing import Optional, Set, Tuple

from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime, parseaddr
from email.generator import BytesGenerator


def decode_mime_header(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def sanitize_component(s: str, max_len: int = 50) -> str:
    """Normalize and make filename-component safe."""
    s = unicodedata.normalize("NFKC", s or "")
    s = s.strip()
    # replace runs of whitespace with single dash
    s = re.sub(r"\s+", "-", s)
    # remove forbidden chars for filenames
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", s)
    # collapse multiple separators
    s = re.sub(r"[-_]{2,}", "-", s)
    # trim
    s = s.strip("-_.")
    if not s:
        return "unknown"
    return s[:max_len]


def get_date_str(msg) -> str:
    date_hdr = msg.get("Date")
    if not date_hdr:
        return "unknown-date"
    try:
        dt = parsedate_to_datetime(date_hdr)
        # if timezone-aware, ensure it doesn't break strftime
        return dt.strftime("%Y-%m-%d")
    except Exception:
        # fallback: sanitize the header a bit
        return sanitize_component(date_hdr, max_len=10)


def compute_message_hash(msg) -> str:
    """
    Compute 8-byte hash (16 hex chars).
    Prefer Message-ID when present (fast & stable).
    Otherwise use Date+From+Subject + first ~1024 bytes of payload.
    """
    msgid = msg.get("Message-ID")
    if msgid:
        key = msgid.strip().encode("utf-8", errors="ignore")
        return hashlib.sha256(key).hexdigest()[:16]

    # otherwise build a fingerprint from headers + small payload sample
    headers_key = "\n".join([
        (msg.get("Date") or "").strip(),
        (msg.get("From") or "").strip(),
        (msg.get("Subject") or "").strip(),
    ]).encode("utf-8", errors="ignore")

    sample = b""
    try:
        if msg.is_multipart():
            # take first non-multipart part that has a payload
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    payload = None
                if payload:
                    sample = payload[:1024]
                    break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                sample = payload[:1024]
    except Exception:
        sample = b""

    key = headers_key + b"|" + sample
    return hashlib.sha256(key).hexdigest()[:16]


def load_existing_hashes(output_dir: Path, hashfile_name: str = "written_hashes.txt") -> Set[str]:
    hashes: Set[str] = set()
    hashfile = output_dir / hashfile_name
    if hashfile.exists():
        with open(hashfile, "r", encoding="utf-8") as hf:
            for line in hf:
                h = line.strip()
                if h:
                    hashes.add(h)
    else:
        # try to glean hashes from existing filenames (pattern: ...-<16hex>.eml)
        pattern = re.compile(r'([0-9a-fA-F]{16})(?:\.eml)$')
        for p in output_dir.glob("*.eml"):
            m = pattern.search(p.name)
            if m:
                hashes.add(m.group(1).lower())
    return hashes


def append_hash_file(output_dir: Path, h: str, hashfile_name: str = "written_hashes.txt") -> None:
    hf = output_dir / hashfile_name
    with open(hf, "a", encoding="utf-8") as f:
        f.write(h + "\n")
        f.flush()
        os.fsync(f.fileno())


def write_eml_stream(message, eml_path: Path) -> None:
    """Stream the message to disk without building a giant bytes object."""
    with open(eml_path, "wb") as f:
        gen = BytesGenerator(f, mangle_from_=False)
        gen.flatten(message)


def convert_streaming(mbox_path: Path, output_dir: Path) -> Tuple[int, int, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    seen_hashes = load_existing_hashes(output_dir)
    mbox = mailbox.mbox(str(mbox_path))

    success = fail = skipped = 0
    for idx, msg in enumerate(mbox, start=1):
        try:
            date_str = get_date_str(msg)
            from_hdr = decode_mime_header(msg.get("From") or "unknown-from")
            name, email_addr = parseaddr(from_hdr)
            from_component = email_addr or name or "unknown-from"
            from_component = sanitize_component(from_component, max_len=30)

            subject = decode_mime_header(msg.get("Subject") or "no-subject")
            subject_component = sanitize_component(subject, max_len=50)

            h = compute_message_hash(msg)
            h = h.lower()

            if h in seen_hashes:
                skipped += 1
                if idx % 10000 == 0:
                    print(f"{idx} processed — success={success}, skipped={skipped}, fail={fail}")
                continue

            filename = f"{date_str}-{from_component}-{subject_component}-{h}.eml"
            eml_path = output_dir / filename

            if eml_path.exists():
                skipped += 1
                seen_hashes.add(h)
                append_hash_file(output_dir, h)
                continue

            # write streaming to disk
            write_eml_stream(msg, eml_path)

            success += 1
            seen_hashes.add(h)
            append_hash_file(output_dir, h)

            if idx % 1000 == 0:
                print(f"{idx} processed — success={success}, skipped={skipped}, fail={fail}")

        except Exception as e:
            fail += 1
            print(f"[ERROR] message {idx}: {e}")

    return success, fail, skipped


def main():
    parser = argparse.ArgumentParser(description="Convert large MBOX to per-message EML files (streaming).")
    parser.add_argument("--file", "-f", required=True, help="Path to input mbox file")
    parser.add_argument("--output_dir", "-o", required=True, help="Directory for output .eml files")
    args = parser.parse_args()

    mbox_path = Path(args.file)
    output_dir = Path(args.output_dir)

    if not mbox_path.exists():
        raise SystemExit(f"Input mbox not found: {mbox_path}")

    success, fail, skipped = convert_streaming(mbox_path, output_dir)
    print(f"\nFertig: {success} geschrieben, {fail} Fehler, {skipped} übersprungen.")


if __name__ == "__main__":
    main()

