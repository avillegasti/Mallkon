#!/usr/bin/env python3
"""Build the dashboard index from cached Yocto metadata artifacts."""

from __future__ import annotations

import json
import os
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ARTIFACT_ROOT = Path(os.environ.get("ARTIFACT_ROOT", "/artifacts"))
DASHBOARD_DATA_DIR = Path(os.environ.get("DASHBOARD_DATA_DIR", ARTIFACT_ROOT / "dashboard"))

REQUIRED_RELEASE_LAYER_NAMES = [
    "meta-northfi-distro",
    "meta-arquimea-distro-base",
    "meta-layout-base",
    "meta-arquimea-security",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_id(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    value = re.sub(r"-+", "-", value).strip("-")
    return value or "unknown"


def read_json_member(archive: tarfile.TarFile, suffix: str) -> dict:
    for member in archive.getmembers():
        if member.isfile() and member.name.endswith(suffix):
            stream = archive.extractfile(member)
            if stream is None:
                return {}
            return json.loads(stream.read().decode("utf-8"))
    return {}


def read_text_member(archive: tarfile.TarFile, name: str) -> str:
    member = archive.getmember(name)
    stream = archive.extractfile(member)
    if stream is None:
        return ""
    return stream.read().decode("utf-8", errors="replace")


def parse_license_manifest(text: str) -> list[dict]:
    packages: list[dict] = []
    current: dict[str, str] = {}
    key_map = {
        "PACKAGE NAME": "name",
        "PACKAGE VERSION": "version",
        "RECIPE NAME": "recipe",
        "LICENSE": "license",
    }
    for raw_line in text.splitlines() + [""]:
        line = raw_line.strip()
        if not line:
            if current.get("name"):
                packages.append({
                    "name": current.get("name", ""),
                    "version": current.get("version", ""),
                    "recipe": current.get("recipe", ""),
                    "license": current.get("license", ""),
                })
            current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized = key_map.get(key.strip())
        if normalized:
            current[normalized] = value.strip()
    return packages


def image_name_from_license_path(path: str) -> str:
    image_dir = Path(path).parent.name
    return re.sub(r"-\d{14}$", "", image_dir)


def select_primary_package_manifest(manifests: list[dict], artifact_label: str) -> dict:
    if not manifests:
        return {"available": False, "packages": [], "images": []}
    non_initramfs = [item for item in manifests if "mfg-initramfs" not in item.get("image", "")]
    candidates = non_initramfs or manifests
    for item in candidates:
        if artifact_label and artifact_label in item.get("image", ""):
            return item
    return candidates[0]


def package_manifest_from_archive(archive: tarfile.TarFile, artifact_label: str) -> dict:
    manifests: list[dict] = []
    for member in archive.getmembers():
        if not member.isfile() or not member.name.endswith("/license.manifest"):
            continue
        if "/deploy-licenses/" not in member.name:
            continue
        text = read_text_member(archive, member.name)
        packages = parse_license_manifest(text)
        if not packages:
            continue
        manifests.append({
            "image": image_name_from_license_path(member.name),
            "source": member.name,
            "package_count": len(packages),
            "packages": packages,
        })
    primary = select_primary_package_manifest(manifests, artifact_label)
    return {
        "schema_version": 1,
        "available": bool(primary.get("packages")),
        "image": primary.get("image", ""),
        "source": primary.get("source", ""),
        "package_count": len(primary.get("packages", [])),
        "packages": primary.get("packages", []),
        "images": [
            {"image": item.get("image", ""), "source": item.get("source", ""), "package_count": item.get("package_count", 0)}
            for item in manifests
        ],
    }


def channel_from_manifest(manifest: dict, release: dict) -> str:
    if release.get("channel"):
        return release["channel"]
    source = manifest.get("source", {})
    if source.get("is_tag"):
        tag = source.get("branch_or_tag", "").lower()
        return "rc" if "-rc." in tag else "release"
    return "development"


def storage_group(channel: str) -> str:
    return "releases" if channel in ("release", "rc") else "development"


def has_real_cve_report(cve: dict) -> bool:
    report_files = cve.get("report_files", [])
    real_reports = [
        report
        for report in report_files
        if not report.endswith(".testdata.json")
    ]
    return bool(real_reports or cve.get("issues"))


def normalize_cve_summary(cve: dict) -> dict:
    if not cve:
        return {"available": False, "issues": []}
    normalized = dict(cve)
    normalized["available"] = has_real_cve_report(cve)
    return normalized


def cve_summary_for_release(cve: dict) -> dict:
    counts = cve.get("counts_by_status", {})
    return {
        "available": has_real_cve_report(cve),
        "unpatched": counts.get("Unpatched", 0),
        "patched": counts.get("Patched", 0),
        "ignored": counts.get("Ignored", 0),
        "unknown": counts.get("Unknown", 0),
        "packages_with_issues": cve.get("packages_with_issues", 0),
        "packages_with_unpatched": cve.get("packages_with_unpatched", 0),
        "report": "cve-summary.json",
    }


def artifact_names(detail: dict) -> list[str]:
    return [artifact.get("name", "") for artifact in detail.get("artifacts", [])]


def flashing_readiness(detail: dict) -> dict:
    names = artifact_names(detail)
    has_boot = any(name.startswith("imx-boot") or name == "boot.itb" for name in names)
    has_wic = any(re.search(r"rootfs\.wic(\.gz|\.zst)?$", name) for name in names)
    has_bmap = any(name.endswith(".wic.bmap") for name in names)
    has_swu = any(name.endswith(".swu") for name in names)
    return {
        "ready": has_boot and has_wic and has_bmap and has_swu,
        "hasBoot": has_boot,
        "hasWic": has_wic,
        "hasBmap": has_bmap,
        "hasSwu": has_swu,
    }


def layer_tag(layer: dict) -> str:
    if layer.get("tag"):
        return layer.get("tag", "")
    tags = layer.get("tags", [])
    if isinstance(tags, list) and tags:
        return tags[0]
    return ""


def release_layer_traceability(detail: dict) -> dict:
    layers = {layer.get("name", ""): layer for layer in detail.get("layers", [])}
    rows = []
    missing_layers = 0
    missing_tags = 0
    for name in REQUIRED_RELEASE_LAYER_NAMES:
        layer = layers.get(name, {})
        tag = layer_tag(layer)
        if not layer:
            missing_layers += 1
        elif not tag:
            missing_tags += 1
        rows.append({
            "name": name,
            "present": bool(layer),
            "tag": tag,
            "commit": layer.get("commit", ""),
            "branch": layer.get("branch", ""),
        })
    return {
        "rows": rows,
        "missing_layers": missing_layers,
        "missing_tags": missing_tags,
        "complete": missing_layers == 0 and missing_tags == 0,
    }


def release_origin_placeholder() -> dict:
    return {
        "available": False,
        "id": "",
        "match": "none",
        "reason": "No matching development build was found for this release commit.",
    }


def entry_label(entry: dict) -> str:
    return entry.get("tag") or entry.get("artifact_label") or entry.get("id", "")


def entry_layer_fingerprint(entry: dict) -> tuple[str, ...]:
    trace = entry.get("layer_traceability", {})
    rows = {row.get("name", ""): row for row in trace.get("rows", [])}
    fingerprint = []
    for name in REQUIRED_RELEASE_LAYER_NAMES:
        commit = rows.get(name, {}).get("commit", "")
        if not commit:
            return ()
        fingerprint.append(commit)
    return tuple(fingerprint)


def origin_candidate_score(release: dict, candidate: dict) -> tuple[int, str]:
    score = 0
    parts = []
    if candidate.get("machine") == release.get("machine"):
        score += 4
        parts.append("machine")
    if candidate.get("kas_manifest") == release.get("kas_manifest"):
        score += 4
        parts.append("manifest")
    if candidate.get("source") == "pr-merge":
        score += 1
    return score, "commit" + ("-" + "-".join(parts) if parts else "")


def release_origin_from_candidate(release: dict, candidate: dict, match_family: str) -> dict:
    _, match = origin_candidate_score(release, candidate)
    if match_family != "commit":
        suffix = match.removeprefix("commit")
        match = match_family + suffix
    return {
        "available": True,
        "id": candidate.get("id", ""),
        "channel": candidate.get("channel", "development"),
        "match": match,
        "label": entry_label(candidate),
        "build_id": candidate.get("build_id", ""),
        "commit": candidate.get("commit", ""),
        "machine": candidate.get("machine", ""),
        "kas_manifest": candidate.get("kas_manifest", ""),
        "generated_at_utc": candidate.get("generated_at_utc", ""),
    }


def link_release_origins(entries: list[dict]) -> None:
    development = [entry for entry in entries if entry.get("channel") == "development"]
    by_commit: dict[str, list[dict]] = {}
    by_layers: dict[tuple[str, ...], list[dict]] = {}
    for entry in development:
        commit = entry.get("commit", "")
        if commit:
            by_commit.setdefault(commit, []).append(entry)
        fingerprint = entry_layer_fingerprint(entry)
        if fingerprint:
            by_layers.setdefault(fingerprint, []).append(entry)

    for candidates in list(by_commit.values()) + list(by_layers.values()):
        candidates.sort(key=lambda item: item.get("generated_at_utc") or item.get("cached_at_utc") or "", reverse=True)

    for entry in entries:
        if entry.get("channel") not in ("release", "rc"):
            continue
        commit = entry.get("commit", "")
        candidates = by_commit.get(commit, [])
        match_family = "commit"
        if not candidates:
            fingerprint = entry_layer_fingerprint(entry)
            candidates = by_layers.get(fingerprint, []) if fingerprint else []
            match_family = "release-layers"
        if not candidates:
            entry["origin_build"] = release_origin_placeholder()
            entry["origin_builds"] = []
            continue
        ranked = sorted(
            candidates,
            key=lambda candidate: (
                origin_candidate_score(entry, candidate)[0],
                candidate.get("generated_at_utc") or candidate.get("cached_at_utc") or "",
            ),
            reverse=True,
        )
        origins = [release_origin_from_candidate(entry, candidate, match_family) for candidate in ranked]
        entry["origin_build"] = origins[0]
        entry["origin_builds"] = origins


def build_detail(manifest: dict, release: dict, cve: dict, packages: dict, archive_path: Path) -> dict:
    source = manifest.get("source", {})
    kas = manifest.get("kas", {})
    azure = manifest.get("azure", {})
    artifact_label = manifest.get("artifact_label") or release.get("artifact_label") or archive_path.stem
    channel = channel_from_manifest(manifest, release)
    generated = release.get("generated_at_utc") or manifest.get("generated_at_utc") or utc_now()

    detail = {
        "schema_version": 1,
        "generated_at_utc": generated,
        "cached_at_utc": datetime.fromtimestamp(archive_path.stat().st_mtime, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "channel": channel,
        "source": "tag" if source.get("is_tag") else "pr-merge",
        "tag": release.get("tag") or (source.get("branch_or_tag") if source.get("is_tag") else ""),
        "commit": release.get("commit") or source.get("commit", ""),
        "artifact_label": artifact_label,
        "machine": release.get("machine") or kas.get("machine", ""),
        "kas_manifest": release.get("kas_manifest") or kas.get("manifest", ""),
        "targets": release.get("targets") or kas.get("targets", []),
        "azure": {
            "build_id": azure.get("build_id", ""),
            "build_number": azure.get("build_number", ""),
            "definition": azure.get("definition", ""),
            "repository": azure.get("repository", ""),
        },
        "published_artifacts": release.get("published_artifacts") or {
            "images": f"yocto-images-{artifact_label}",
            "metadata": f"yocto-metadata-{artifact_label}",
            "release_metadata": "",
        },
        "artifacts": release.get("artifacts") or manifest.get("artifacts", []),
        "layers": release.get("layers") or manifest.get("layers", []),
        "metadata": {
            "build_manifest": "build-manifest.json",
            "package_manifest": "package-manifest.json",
            "checksums": "SHA256SUMS.txt",
            "source_archive": str(archive_path),
        },
        "package_manifest": {
            "available": packages.get("available", False),
            "image": packages.get("image", ""),
            "package_count": packages.get("package_count", 0),
            "source": packages.get("source", ""),
        },
        "cve_summary": cve_summary_for_release(cve),
    }
    return detail


def index_entry(detail: dict, relative_dir: str, cve: dict | None = None) -> dict:
    cve_summary = detail.get("cve_summary", {})
    cve = cve or {}
    return {
        "id": safe_id(relative_dir),
        "channel": detail.get("channel", "development"),
        "source": detail.get("source", ""),
        "tag": detail.get("tag", ""),
        "commit": detail.get("commit", ""),
        "artifact_label": detail.get("artifact_label", ""),
        "machine": detail.get("machine", ""),
        "kas_manifest": detail.get("kas_manifest", ""),
        "generated_at_utc": detail.get("generated_at_utc", ""),
        "cached_at_utc": detail.get("cached_at_utc", ""),
        "build_id": detail.get("azure", {}).get("build_id", ""),
        "artifact_count": len(detail.get("artifacts", [])),
        "cve_summary": cve_summary,
        "cve_severity": cve.get("counts_by_severity", {}),
        "cve_issue_count": len(cve.get("issues", [])) if isinstance(cve.get("issues", []), list) else 0,
        "flashing": flashing_readiness(detail),
        "layer_traceability": release_layer_traceability(detail),
        "release_json": f"{relative_dir}/release.json",
        "cve_summary_path": f"{relative_dir}/cve-summary.json",
        "build_manifest": f"{relative_dir}/build-manifest.json",
        "package_manifest_path": f"{relative_dir}/package-manifest.json",
        "package_manifest": detail.get("package_manifest", {}),
        "published_artifacts": detail.get("published_artifacts", {}),
    }


def metadata_archives() -> list[Path]:
    archives: list[Path] = []
    for channel in ("releases", "development"):
        root = ARTIFACT_ROOT / channel
        if root.is_dir():
            archives.extend(sorted(root.rglob("yocto-metadata-*.tar.gz")))
    return archives


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o664)


def write_index(path: Path, entries: list[dict]) -> None:
    index = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "releases": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(index, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).chmod(0o664)
    Path(temp_name).replace(path)


def rebuild() -> None:
    entries = []
    grouped_entries = {"releases": [], "development": []}
    for archive_path in metadata_archives():
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                manifest = read_json_member(archive, "build-manifest.json")
                if not manifest:
                    continue
                cve = read_json_member(archive, "cve-summary.json")
                release = read_json_member(archive, "release.json")
                artifact_label = manifest.get("artifact_label") or release.get("artifact_label") or archive_path.stem
                packages = package_manifest_from_archive(archive, artifact_label)
        except (OSError, tarfile.TarError, json.JSONDecodeError, KeyError) as exc:
            print(f"Skipping {archive_path}: {exc}")
            continue

        normalized_cve = normalize_cve_summary(cve)
        detail = build_detail(manifest, release, normalized_cve, packages, archive_path)
        channel = detail.get("channel", "development")
        group = storage_group(channel)
        source_id = safe_id(archive_path.parent.name)
        relative_dir = f"{group}/{source_id}"
        output_dir = DASHBOARD_DATA_DIR / relative_dir

        write_json(output_dir / "release.json", detail)
        write_json(output_dir / "build-manifest.json", manifest)
        write_json(output_dir / "package-manifest.json", packages)
        write_json(output_dir / "cve-summary.json", normalized_cve)
        entry = index_entry(detail, relative_dir, normalized_cve)
        entries.append(entry)
        grouped_entries[group].append(entry)

    sort_key = lambda item: item.get("generated_at_utc") or item.get("cached_at_utc") or ""
    entries.sort(key=sort_key, reverse=True)
    link_release_origins(entries)
    grouped_entries = {"releases": [], "development": []}
    for entry in entries:
        grouped_entries[storage_group(entry.get("channel", "development"))].append(entry)
    for group_entries in grouped_entries.values():
        group_entries.sort(key=sort_key, reverse=True)

    write_index(DASHBOARD_DATA_DIR / "releases" / "index.json", grouped_entries["releases"])
    write_index(DASHBOARD_DATA_DIR / "development" / "index.json", grouped_entries["development"])
    write_index(DASHBOARD_DATA_DIR / "releases-index.json", entries)
    print(
        f"Indexed {len(grouped_entries['releases'])} release builds and "
        f"{len(grouped_entries['development'])} development builds into {DASHBOARD_DATA_DIR}"
    )


if __name__ == "__main__":
    rebuild()
