#!/usr/bin/env python3
"""
JLMAI canary tripwires ("honeypot" decoys).

A canary is a file that should never be touched. plant_canary() writes a
high-entropy random token into a decoy file and seals its SHA-256 in a seal
record. check_canaries() re-hashes every canary and reports any that are
missing or modified — evidence that someone or something poked where it
should not have.

Canary *tokens* are the same idea for credentials: random strings that look
like API keys. Plant one in a config file; if the token ever shows up in a
log, a request, or an alert, the decoy was harvested.

Typical use:
    canary.py plant ./config/.aws_canary --seal /secure/canaries.json \\
        --label "decoy AWS key - alerts if read"
    canary.py check --seal /secure/canaries.json   # run on a schedule

Honest limits:
- Tripwires detect tampering AFTER THE FACT, on the next check. They are
  not real-time intrusion detection and they do not block anything.
- The seal record must live where an attacker cannot rewrite it (separate
  host, append-only store, or a signed file). A canary whose seal the
  attacker can also modify detects nothing.
- Canaries reveal an intruder; they do not stop one. They are one layer,
  not a security posture.
"""

import argparse
import hashlib
import json
import logging
import os
import secrets
import sys
from datetime import datetime, timezone

logger = logging.getLogger("JLMAI-Canary")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def new_token(nbytes: int = 32) -> str:
    """A fresh high-entropy hex token (never reuse a token)."""
    return secrets.token_hex(nbytes)


def _load_seal(seal_path: str) -> dict:
    if os.path.isfile(seal_path):
        with open(seal_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data.setdefault("canaries", {})
        return data
    return {"created": datetime.now(timezone.utc).isoformat(), "canaries": {}}


def _save_seal(seal_path: str, data: dict) -> None:
    tmp = seal_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, seal_path)


def plant_canary(path: str, seal_path: str, label: str = "") -> str:
    """
    Write a random token to `path` and seal its hash. Returns the token.
    Refuses to overwrite an existing file — a canary must be a fresh decoy.
    """
    if os.path.exists(path):
        raise FileExistsError("refusing to overwrite existing file: %s" % path)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    token = new_token()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# CANARY - decoy file. Do not use, do not delete.\n")
        fh.write("token=%s\n" % token)
    digest = hashlib.sha256(token.encode()).hexdigest()
    seal = _load_seal(seal_path)
    seal["canaries"][os.path.abspath(path)] = {
        "label": label,
        "sha256": digest,
        "planted_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_seal(seal_path, seal)
    logger.info("planted canary: %s (%s)", path, label or "no label")
    return token


def check_canaries(seal_path: str):
    """
    Return (tripped, ok) where each is a list of dicts describing the
    canary. A canary trips when its file is missing or its token changed.
    """
    if not os.path.isfile(seal_path):
        raise FileNotFoundError("no seal record: %s" % seal_path)
    seal = _load_seal(seal_path)
    tripped, ok = [], []
    for path, info in seal["canaries"].items():
        entry = {"path": path, "label": info.get("label", "")}
        if not os.path.isfile(path):
            entry["reason"] = "missing"
            tripped.append(entry)
            continue
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        token = ""
        for line in content.splitlines():
            if line.startswith("token="):
                token = line.split("=", 1)[1].strip()
        if hashlib.sha256(token.encode()).hexdigest() != info["sha256"]:
            entry["reason"] = "modified"
            tripped.append(entry)
        else:
            ok.append(entry)
    return tripped, ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="Canary tripwire (honeypot decoy) manager")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plant", help="plant a new canary decoy file")
    p.add_argument("path")
    p.add_argument("--seal", required=True, help="seal record JSON")
    p.add_argument("--label", default="")

    c = sub.add_parser("check", help="check all canaries against the seal")
    c.add_argument("--seal", required=True, help="seal record JSON")

    t = sub.add_parser("token", help="print a fresh canary token (for configs)")
    t.add_argument("--bytes", type=int, default=32)

    args = ap.parse_args(argv)
    if args.cmd == "plant":
        try:
            plant_canary(args.path, args.seal, args.label)
        except FileExistsError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
    elif args.cmd == "check":
        try:
            tripped, ok = check_canaries(args.seal)
        except FileNotFoundError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        if tripped:
            print("TRIPPED CANARIES (%d):" % len(tripped))
            for entry in tripped:
                print("  - %s [%s]: %s" % (entry["path"], entry["label"], entry["reason"]))
                logger.warning("canary tripped: %s (%s)", entry["path"], entry["reason"])
            return 2
        print("OK: %d canaries intact" % len(ok))
    elif args.cmd == "token":
        print(new_token(args.bytes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
