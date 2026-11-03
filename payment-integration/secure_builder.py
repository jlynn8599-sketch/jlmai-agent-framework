"""Build and verify deterministic-ish ZIP releases with an unsigned SHA-256 manifest.

This module provides integrity checking, not cryptographic authenticity: the manifest
is unsigned and must be authenticated separately (for example, with a trusted signature).
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable


class ReleaseError(Exception):
    """Raised when a release cannot be safely built or verified."""


_DEFAULT_EXCLUDES = (
    ".git/**", ".git", "venv/**", ".venv/**", "__pycache__/**",
    ".pytest_cache/**", "target/**", "node_modules/**", "build/**",
    "dist/**", ".env", ".env.*", "*.env", "*.secret", "*secret*",
    "*.key", "*.pem", "*.p12", "*.pfx", "id_rsa", "id_ed25519",
    "config/env.secret", "*.pyc", ".DS_Store",
)


def _validate_version(version: str) -> str:
    """Validate a version token so it cannot become a path or filename traversal."""
    if not isinstance(version, str) or not version or len(version) > 64:
        raise ReleaseError("Invalid version: expected 1-64 safe characters")
    if ".." in version or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", version):
        raise ReleaseError(f"Unsafe version: {version!r}")
    return version


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_excluded(relative_path: str, patterns: Iterable[str]) -> bool:
    path = PurePosixPath(relative_path)
    name = path.name
    for pattern in patterns:
        normalized = pattern.replace("\\", "/").rstrip("/")
        if not normalized:
            continue
        if fnmatch.fnmatchcase(relative_path, normalized) or path.match(normalized):
            return True
        # Directory-style patterns should also match descendants.
        if normalized.endswith("/**"):
            base = normalized[:-3].rstrip("/")
            if relative_path == base or relative_path.startswith(base + "/"):
                return True
        if "/" not in normalized and fnmatch.fnmatchcase(name, normalized):
            return True
    return False


def _safe_relative_path(path: str) -> bool:
    if not path or "\\" in path or path.startswith("/"):
        return False
    parsed = PurePosixPath(path)
    return not any(part in ("", ".", "..") for part in parsed.parts) and not parsed.is_absolute()


def build_release(source_dir, output_dir, version: str, excludes=None) -> dict:
    """Package source files and write a sidecar JSON manifest.

    Returns a dict containing ``archive``, ``manifest``, ``version``, and ``file_count``.
    The output directory should be outside the source tree to avoid packaging artifacts.
    """
    version = _validate_version(version)
    source = Path(source_dir).resolve()
    output = Path(output_dir).resolve()
    if not source.exists() or not source.is_dir():
        raise ReleaseError(f"Source directory does not exist or is not a directory: {source}")
    try:
        output.relative_to(source)
    except ValueError:
        pass
    else:
        raise ReleaseError("Output directory must not be inside the source directory")

    patterns = tuple(_DEFAULT_EXCLUDES) + tuple(excludes or ())
    candidates = []
    for path in source.rglob("*"):
        # Do not follow symlink files or directories; avoid packaging external content.
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(source).as_posix()
        if _is_excluded(rel, patterns):
            continue
        if not _safe_relative_path(rel):
            raise ReleaseError(f"Unsafe source path: {rel!r}")
        candidates.append((rel, path))
    candidates.sort(key=lambda item: item[0])

    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"release-{version}.zip"
    manifest_path = output / f"release-{version}.manifest.json"
    file_entries = []
    # Create a temporary archive and atomically replace the final path.
    fd, temp_name = tempfile.mkstemp(prefix=".release-", suffix=".zip.tmp", dir=str(output))
    os.close(fd)
    temp_archive = Path(temp_name)
    try:
        with zipfile.ZipFile(temp_archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel, path in candidates:
                data = path.read_bytes()
                info = zipfile.ZipInfo(rel)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100644 & 0xFFFF) << 16
                zf.writestr(info, data)
                file_entries.append({"path": rel, "sha256": _sha256_bytes(data), "size": len(data)})
        os.replace(temp_archive, archive)
    except Exception as exc:
        try:
            temp_archive.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"Failed to create release archive: {exc}") from exc

    manifest = {
        "schema_version": 1,
        "version": version,
        "archive": archive.name,
        "archive_sha256": _sha256_file(archive),
        "file_count": len(file_entries),
        "files": file_entries,
        "authenticity": "NOT_VERIFIED_UNSIGNED_MANIFEST",
    }
    temp_manifest = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    try:
        temp_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp_manifest, manifest_path)
    except Exception as exc:
        temp_manifest.unlink(missing_ok=True)
        raise ReleaseError(f"Failed to write release manifest: {exc}") from exc

    return {"archive": str(archive), "manifest": str(manifest_path), "version": version, "file_count": len(file_entries)}


def verify_release(archive_path, manifest_path=None) -> dict:
    """Verify archive SHA-256, member uniqueness, and each manifest file digest."""
    archive = Path(archive_path)
    if not archive.is_file():
        raise ReleaseError(f"Archive not found: {archive}")
    if manifest_path is None:
        manifest_path = archive.with_name(archive.stem + ".manifest.json")
    manifest_file = Path(manifest_path)
    if not manifest_file.is_file():
        raise ReleaseError(f"Manifest not found: {manifest_file}")
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"Invalid manifest JSON: {exc}") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ReleaseError("Invalid manifest structure")
    if manifest.get("archive_sha256") != _sha256_file(archive):
        raise ReleaseError("Archive SHA-256 does not match manifest")

    manifest_paths = []
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ReleaseError("Invalid file entry in manifest")
        path = entry["path"]
        if not _safe_relative_path(path):
            raise ReleaseError(f"Unsafe manifest path: {path!r}")
        manifest_paths.append(path)
    if len(manifest_paths) != len(set(manifest_paths)):
        raise ReleaseError("Duplicate path in manifest")
    if manifest.get("file_count") != len(manifest_paths):
        raise ReleaseError("Manifest file_count does not match files list")

    try:
        with zipfile.ZipFile(archive, "r") as zf:
            infos = zf.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ReleaseError("Duplicate ZIP member names")
            if any(not _safe_relative_path(name) for name in names):
                raise ReleaseError("Unsafe path in ZIP archive")
            if set(names) != set(manifest_paths):
                raise ReleaseError("ZIP members do not match manifest paths")
            for entry in manifest["files"]:
                data = zf.read(entry["path"])
                if entry.get("size") != len(data):
                    raise ReleaseError(f"File size mismatch: {entry['path']}")
                if entry.get("sha256") != _sha256_bytes(data):
                    raise ReleaseError(f"File SHA-256 mismatch: {entry['path']}")
    except (zipfile.BadZipFile, OSError, RuntimeError, KeyError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"Unable to verify ZIP archive: {exc}") from exc

    return {
        "status": "PASS",
        "file_count": len(manifest_paths),
        "authenticity": "NOT_VERIFIED_UNSIGNED_MANIFEST",
        "version": manifest.get("version"),
        "archive_sha256": manifest["archive_sha256"],
    }
