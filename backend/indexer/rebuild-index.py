#!/usr/bin/env python3
"""Build the dashboard index from cached Yocto metadata artifacts."""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import tempfile
import uuid
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


def strip_archive_root(path: str) -> str:
    parts = Path(path).parts
    if len(parts) > 1 and parts[1] == "deploy-sbom":
        return str(Path(*parts[1:]))
    return path


def sbom_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    return [
        member
        for member in archive.getmembers()
        if member.isfile()
        and "/deploy-sbom/" in member.name
        and member.name.endswith(".spdx.json")
    ]


def sbom_target_terms(detail: dict, manifest: dict, artifact_label: str) -> set[str]:
    terms = set()
    for target in detail.get("targets") or manifest.get("kas", {}).get("targets", []):
        if not target:
            continue
        value = str(target).lower()
        terms.add(value)
        if value.startswith("swupdate-"):
            terms.add(value.removeprefix("swupdate-"))
    for artifact in detail.get("artifacts", []):
        name = str(artifact.get("name", "")).lower()
        match = re.match(r"^(swupdate-[a-z0-9._-]+?)-verdin-", name)
        if match:
            terms.add(match.group(1))
            terms.add(match.group(1).removeprefix("swupdate-"))
        match = re.match(r"^([a-z0-9._-]+?)-verdin-", name)
        if match:
            terms.add(match.group(1))
    for part in re.split(r"[^a-z0-9._-]+", artifact_label.lower()):
        if "image" in part or "swupdate" in part:
            terms.add(part)
    return {term for term in terms if len(term) >= 4}


def classify_sbom_member(member: tarfile.TarInfo, machine: str, terms: set[str]) -> str:
    del machine
    relative = strip_archive_root(member.name)
    parts = Path(relative).parts
    basename = Path(relative).name.lower()
    if len(parts) >= 4 and parts[0] == "deploy-sbom" and parts[2] == "recipes" and basename.startswith("recipe-"):
        if any(term in basename for term in terms):
            return "primary"
        return "recipe"
    if len(parts) >= 4 and parts[0] == "deploy-sbom" and parts[2] == "runtime":
        return "runtime"
    return "support"


def read_spdx_metadata(archive: tarfile.TarFile, member: tarfile.TarInfo) -> dict:
    stream = archive.extractfile(member)
    if stream is None:
        return {}
    try:
        data = json.loads(stream.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return {
        "spdx_version": data.get("spdxVersion", ""),
        "document_name": data.get("name", ""),
        "document_namespace": data.get("documentNamespace", ""),
        "external_document_refs": len(data.get("externalDocumentRefs", [])),
        "relationships": len(data.get("relationships", [])),
        "packages": len(data.get("packages", [])),
    }


def cyclonedx_license_entries(value: str) -> list[dict]:
    license_value = str(value or "").strip()
    if not license_value or license_value in {"NOASSERTION", "CLOSED"}:
        return []
    return [{"expression": license_value}]


def cyclonedx_component_ref(pkg: dict, index: int) -> str:
    name = safe_id(pkg.get("name", "package"))
    version = safe_id(pkg.get("version", "unknown"))
    recipe = safe_id(pkg.get("recipe", "unknown"))
    return f"yocto:package:{name}:{version}:{recipe}:{index}"


def cyclonedx_component(pkg: dict, index: int) -> dict:
    component = {
        "type": "library",
        "bom-ref": cyclonedx_component_ref(pkg, index),
        "name": pkg.get("name", ""),
        "version": pkg.get("version", ""),
        "properties": [
            {"name": "yocto:recipe", "value": pkg.get("recipe", "")},
        ],
    }
    licenses = cyclonedx_license_entries(pkg.get("license", ""))
    if licenses:
        component["licenses"] = licenses
    return component


def cyclonedx_bom(detail: dict, package_manifest: dict, sbom: dict, relative_dir: str) -> dict:
    packages = sorted(
        package_manifest.get("packages", []),
        key=lambda item: (item.get("name", ""), item.get("version", ""), item.get("recipe", "")),
    )
    components = [cyclonedx_component(pkg, index) for index, pkg in enumerate(packages, start=1)]
    artifact_label = detail.get("artifact_label") or detail.get("tag") or relative_dir
    metadata_component = {
        "type": "firmware",
        "bom-ref": f"yocto:image:{safe_id(artifact_label)}",
        "name": artifact_label,
        "version": detail.get("tag") or artifact_label,
        "properties": [
            {"name": "yocto:machine", "value": detail.get("machine", "")},
            {"name": "yocto:channel", "value": detail.get("channel", "")},
            {"name": "yocto:kas_manifest", "value": detail.get("kas_manifest", "")},
            {"name": "yocto:package_manifest", "value": package_manifest.get("source", "")},
            {"name": "spdx:document_count", "value": str(sbom.get("document_count", 0))},
        ],
    }
    external_references = []
    bundle_path = sbom.get("bundle", {}).get("path", "")
    if bundle_path:
        external_references.append({
            "type": "bom",
            "url": f"data/{bundle_path}",
            "comment": "Source SPDX 2.2 JSON document bundle",
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, relative_dir + ':cyclonedx')}",
        "version": 1,
        "metadata": {
            "timestamp": detail.get("generated_at_utc") or utc_now(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "northfi-release-dashboard",
                        "version": "1",
                    }
                ]
            },
            "component": metadata_component,
        },
        "components": components,
        "externalReferences": external_references,
    }


def write_cyclonedx_bom(output_dir: Path, relative_dir: str, detail: dict, package_manifest: dict, sbom: dict) -> dict:
    target_path = output_dir / "sbom" / "cyclonedx.json"
    bom = cyclonedx_bom(detail, package_manifest, sbom, relative_dir)
    write_json(target_path, bom)
    return {
        "label": "CycloneDX JSON",
        "path": f"{relative_dir}/sbom/cyclonedx.json",
        "format": "CycloneDX 1.5 JSON",
        "component_count": len(bom.get("components", [])),
        "size_bytes": target_path.stat().st_size if target_path.exists() else 0,
    }


def copy_archive_member(archive: tarfile.TarFile, member: tarfile.TarInfo, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stream = archive.extractfile(member)
    if stream is None:
        return
    with output_path.open("wb") as handle:
        shutil.copyfileobj(stream, handle)
    output_path.chmod(0o664)


def write_sbom_bundle(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    output_path: Path,
    archive_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and output_path.stat().st_mtime >= archive_path.stat().st_mtime:
        return
    temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    with tarfile.open(temp_path, "w:gz") as bundle:
        for member in members:
            stream = archive.extractfile(member)
            if stream is None:
                continue
            info = tarfile.TarInfo(strip_archive_root(member.name))
            info.size = member.size
            info.mtime = member.mtime
            info.mode = 0o664
            bundle.addfile(info, stream)
    temp_path.chmod(0o664)
    temp_path.replace(output_path)


def sbom_manifest_from_archive(
    archive: tarfile.TarFile,
    detail: dict,
    manifest: dict,
    package_manifest: dict,
    artifact_label: str,
    relative_dir: str,
    output_dir: Path,
    archive_path: Path,
) -> dict:
    members = sbom_members(archive)
    if not members:
        return {
            "available": False,
            "format": "SPDX-2.2 JSON",
            "documents": [],
            "document_count": 0,
        }

    machine = detail.get("machine", "")
    terms = sbom_target_terms(detail, manifest, artifact_label)
    classified = [(member, classify_sbom_member(member, machine, terms)) for member in members]
    primary_members = [member for member, kind in classified if kind == "primary"]
    if not primary_members:
        primary_members = [member for member, kind in classified if kind == "recipe"][:5]

    sbom_dir = output_dir / "sbom"
    documents = []
    for member in primary_members[:12]:
        relative_source = strip_archive_root(member.name)
        target_name = Path(relative_source).name
        target_path = sbom_dir / target_name
        copy_archive_member(archive, member, target_path)
        metadata = read_spdx_metadata(archive, member)
        documents.append({
            "label": metadata.get("document_name") or target_name.removesuffix(".spdx.json"),
            "type": classify_sbom_member(member, machine, terms),
            "format": "SPDX-2.2 JSON",
            "path": f"{relative_dir}/sbom/{target_name}",
            "source": relative_source,
            "size_bytes": member.size,
            **metadata,
        })

    bundle_path = sbom_dir / "sbom-spdx.tar.gz"
    write_sbom_bundle(archive, members, bundle_path, archive_path)
    counts = {}
    for _, kind in classified:
        counts[kind] = counts.get(kind, 0) + 1

    sbom = {
        "available": True,
        "format": "SPDX-2.2 JSON",
        "profile": "OpenEmbedded create-spdx.bbclass",
        "document_count": len(members),
        "counts": counts,
        "documents": documents,
        "bundle": {
            "label": "Complete SPDX JSON bundle",
            "path": f"{relative_dir}/sbom/sbom-spdx.tar.gz",
            "format": "SPDX-2.2 JSON documents in tar.gz",
            "document_count": len(members),
            "size_bytes": bundle_path.stat().st_size if bundle_path.exists() else 0,
        },
    }
    sbom["cyclonedx"] = write_cyclonedx_bom(output_dir, relative_dir, detail, package_manifest, sbom)
    return sbom


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
    sbom = detail.get("sbom", {})
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
        "sbom_manifest_path": f"{relative_dir}/sbom-manifest.json",
        "sbom": {
            "available": bool(sbom.get("available")),
            "format": sbom.get("format", ""),
            "document_count": sbom.get("document_count", 0),
            "bundle": sbom.get("bundle", {}),
            "cyclonedx": sbom.get("cyclonedx", {}),
            "documents": sbom.get("documents", []),
        },
        "published_artifacts": detail.get("published_artifacts", {}),
    }


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


def metadata_archives() -> list[tuple[str, Path]]:
    archives: list[tuple[str, Path]] = []
    
    # 1. Check for project-specific subdirectories: ARTIFACT_ROOT / "projects" / <project_id> / {releases,development}
    projects_dir = ARTIFACT_ROOT / "projects"
    if projects_dir.is_dir():
        for proj_dir in projects_dir.iterdir():
            if proj_dir.is_dir():
                project_id = proj_dir.name
                for channel in ("releases", "development"):
                    root = proj_dir / channel
                    if root.is_dir():
                        for path in sorted(root.rglob("yocto-metadata-*.tar.gz")):
                            archives.append((project_id, path))
                            
    # 2. Fallback / legacy support: ARTIFACT_ROOT / {releases,development} (associated with 'default' project)
    for channel in ("releases", "development"):
        root = ARTIFACT_ROOT / channel
        if root.is_dir():
            for path in sorted(root.rglob("yocto-metadata-*.tar.gz")):
                # Ensure we don't index the same archive twice if it falls under projects/ default folder
                if "projects/" not in str(path):
                    archives.append(("default", path))
                    
    return archives


def rebuild() -> None:
    # Group entries by project
    project_entries = {}
    
    for project_id, archive_path in metadata_archives():
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                manifest = read_json_member(archive, "build-manifest.json")
                if not manifest:
                    continue
                cve = read_json_member(archive, "cve-summary.json")
                release = read_json_member(archive, "release.json")
                artifact_label = manifest.get("artifact_label") or release.get("artifact_label") or archive_path.stem
                packages = package_manifest_from_archive(archive, artifact_label)
                normalized_cve = normalize_cve_summary(cve)
                detail = build_detail(manifest, release, normalized_cve, packages, archive_path)
                channel = detail.get("channel", "development")
                group = storage_group(channel)
                source_id = safe_id(archive_path.parent.name)
                
                # Output paths are now project-scoped: projects/<project_id>/<group>/<source_id>
                relative_dir = f"projects/{project_id}/{group}/{source_id}"
                output_dir = DASHBOARD_DATA_DIR / relative_dir
                
                sbom = sbom_manifest_from_archive(archive, detail, manifest, packages, artifact_label, relative_dir, output_dir, archive_path)
                detail["metadata"]["sbom_manifest"] = "sbom-manifest.json"
                detail["sbom"] = sbom
        except (OSError, tarfile.TarError, json.JSONDecodeError, KeyError) as exc:
            print(f"Skipping {archive_path}: {exc}")
            continue

        write_json(output_dir / "release.json", detail)
        write_json(output_dir / "build-manifest.json", manifest)
        write_json(output_dir / "package-manifest.json", packages)
        write_json(output_dir / "cve-summary.json", normalized_cve)
        write_json(output_dir / "sbom-manifest.json", detail["sbom"])
        
        entry = index_entry(detail, relative_dir, normalized_cve)
        
        if project_id not in project_entries:
            project_entries[project_id] = []
        project_entries[project_id].append(entry)

    # For each project, generate its index files
    for project_id, entries in project_entries.items():
        sort_key = lambda item: item.get("generated_at_utc") or item.get("cached_at_utc") or ""
        entries.sort(key=sort_key, reverse=True)
        link_release_origins(entries)
        
        grouped_entries = {"releases": [], "development": []}
        for entry in entries:
            # Re-extract channel group from relative path or entry
            channel = entry.get("channel", "development")
            grouped_entries[storage_group(channel)].append(entry)
            
        for group_entries in grouped_entries.values():
            group_entries.sort(key=sort_key, reverse=True)

        project_dir = DASHBOARD_DATA_DIR / "projects" / project_id
        write_index(project_dir / "releases" / "index.json", grouped_entries["releases"])
        write_index(project_dir / "development" / "index.json", grouped_entries["development"])
        write_index(project_dir / "releases-index.json", entries)
        
        # Legacy compatibility for 'default' project at root
        if project_id == "default":
            write_index(DASHBOARD_DATA_DIR / "releases" / "index.json", grouped_entries["releases"])
            write_index(DASHBOARD_DATA_DIR / "development" / "index.json", grouped_entries["development"])
            write_index(DASHBOARD_DATA_DIR / "releases-index.json", entries)
            
        print(
            f"Indexed project '{project_id}': {len(grouped_entries['releases'])} release builds and "
            f"{len(grouped_entries['development'])} development builds into {project_dir}"
        )


if __name__ == "__main__":
    rebuild()
