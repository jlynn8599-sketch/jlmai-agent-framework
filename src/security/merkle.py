#!/usr/bin/env python3
"""
JLMAI Merkle-tree provenance.

Builds a binary Merkle tree over release artifacts so that a single root
hash commits to the exact contents of every file. Inclusion proofs let
anyone verify one artifact against the published root without the whole
tree.

Domain separation (prevents leaf/node second-preimage confusion):
    leaf hash = SHA256(b"\\x00" + file_bytes)
    node hash = SHA256(b"\\x01" + left_child + right_child)
An odd node is paired with itself (standard duplication).

File order is sorted by path, so the root is deterministic for a given
set of files.

Honest limits:
- A Merkle root proves INTEGRITY (files unchanged since the root was
  published), not authenticity on its own. Publish the root inside a
  GPG-signed manifest (see provenance-generate-corrected.sh).
- Security rests on SHA-256 collision resistance. A break in SHA-256
  breaks this tree.
- This proves *what the files were*, not *who made them* — that is what
  the signed commits are for.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    """Hash of a single file's bytes (domain-separated leaf)."""
    return _sha256(LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash of an internal node (domain-separated)."""
    return _sha256(NODE_PREFIX + left + right)


def build_levels(leaf_hashes):
    """Return all tree levels, bottom-up. levels[0] are the leaves."""
    if not leaf_hashes:
        raise ValueError("need at least one leaf")
    levels = [list(leaf_hashes)]
    current = levels[0]
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            nxt.append(node_hash(left, right))
        levels.append(nxt)
        current = nxt
    return levels


def merkle_root(files: dict) -> bytes:
    """Root hash for {path: file_bytes}, sorted by path for determinism."""
    leaves = [leaf_hash(files[p]) for p in sorted(files)]
    return build_levels(leaves)[-1][0]


def inclusion_proof(files: dict, target_path: str):
    """
    Return [(sibling_hash_hex, sibling_is_left), ...] proving target_path
    is committed to by the tree root. Raises ValueError if path not present.
    """
    paths = sorted(files)
    idx = paths.index(target_path)
    levels = build_levels([leaf_hash(files[p]) for p in paths])
    proof = []
    for level in levels[:-1]:
        if idx ^ 1 < len(level):
            sib = level[idx ^ 1]
        else:
            sib = level[idx]  # duplicated odd node
        proof.append((sib.hex(), (idx % 2) == 1))
        idx //= 2
    return proof


def verify_proof(file_bytes: bytes, proof, root_hex: str) -> bool:
    """Check an inclusion proof against a root hash (hex)."""
    h = leaf_hash(file_bytes)
    for sib_hex, sib_is_left in proof:
        sib = bytes.fromhex(sib_hex)
        h = node_hash(sib, h) if sib_is_left else node_hash(h, sib)
    return h.hex() == root_hex


def manifest_for_files(files: dict) -> dict:
    """Build a signed-ready manifest dict for {path: file_bytes}."""
    root = merkle_root(files)
    return {
        "algorithm": "sha256-merkle-v1",
        "created": datetime.now(timezone.utc).isoformat(),
        "files": {p: hashlib.sha256(files[p]).hexdigest() for p in sorted(files)},
        "merkle_root": root.hex(),
    }


def collect_files(root_dir, skip_dirs=("__pycache__", ".git")):
    """Read every file under root_dir into {relpath: bytes}."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root_dir)
            with open(full, "rb") as fh:
                out[rel] = fh.read()
    if not out:
        raise ValueError("no files found under %s" % root_dir)
    return out


def verify_directory(manifest: dict, root_dir: str, exclude=()):
    """Return (ok: bool, problems: list[str]).

    Flags missing, modified, AND newly added files. Previously the root
    was recomputed over only the manifest's files, so an added file was
    silently ignored; the root is now computed over the full directory
    and any file not in the manifest is reported explicitly.

    `exclude` is a list of relpaths (e.g. the manifest file itself, when
    it lives inside root_dir) to ignore — otherwise build+verify in the
    same directory would always flag its own manifest as added.
    """
    problems = []
    try:
        files = collect_files(root_dir)
    except ValueError as exc:
        return False, [str(exc)]
    for rel in exclude:
        files.pop(rel, None)
    manifest_files = manifest.get("files", {})
    for path, expected_hex in manifest_files.items():
        full = os.path.join(root_dir, path)
        if not os.path.isfile(full):
            problems.append("missing: %s" % path)
            continue
        with open(full, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
        if actual != expected_hex:
            problems.append("modified: %s" % path)
    for path in sorted(set(files) - set(manifest_files)):
        problems.append("added: %s" % path)
    actual_root = merkle_root(files)
    if problems or actual_root.hex() != manifest.get("merkle_root"):
        if not problems:
            problems.append("merkle root mismatch (file set changed)")
        return False, problems
    return True, []


def main(argv=None):
    ap = argparse.ArgumentParser(description="Merkle-tree provenance for release artifacts")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build Merkle manifest for a directory")
    b.add_argument("directory")
    b.add_argument("-o", "--output", default="merkle-manifest.json")

    v = sub.add_parser("verify", help="verify a directory against a manifest")
    v.add_argument("manifest")
    v.add_argument("directory")

    p = sub.add_parser("prove", help="print inclusion proof for one file")
    p.add_argument("directory")
    p.add_argument("path")

    args = ap.parse_args(argv)
    if args.cmd == "build":
        manifest = manifest_for_files(collect_files(args.directory))
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        print("merkle_root=%s" % manifest["merkle_root"])
        print("files=%d -> %s" % (len(manifest["files"]), args.output))
    elif args.cmd == "verify":
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        # Ignore the manifest itself if it lives inside the verified dir.
        try:
            rel_manifest = os.path.relpath(os.path.abspath(args.manifest),
                                           os.path.abspath(args.directory))
            exclude = [] if rel_manifest.startswith("..") else [rel_manifest]
        except ValueError:
            exclude = []
        ok, problems = verify_directory(manifest, args.directory, exclude=exclude)
        if ok:
            print("OK: %d files verified, root %s" %
                  (len(manifest["files"]), manifest["merkle_root"]))
        else:
            print("FAILED:")
            for prob in problems:
                print("  -", prob)
            return 1
    elif args.cmd == "prove":
        files = collect_files(args.directory)
        if args.path not in files:
            print("not in tree: %s" % args.path, file=sys.stderr)
            return 1
        root = merkle_root(files).hex()
        proof = inclusion_proof(files, args.path)
        print(json.dumps({"path": args.path, "root": root, "proof": proof}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
