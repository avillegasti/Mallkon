import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("PORTAL_DB_PATH", "/data/portal.db")
VALID_STATUSES = {"Draft", "Under review", "Blocked", "Approved", "Released"}
CHECKLIST = [
    ("cve_reviewed", "CVEs reviewed", "Open CVEs were inspected and accepted or assigned."),
    ("full_cve_export_reviewed", "Full CVE export attached/reviewed", "CSV/JSON export was generated, attached if needed, and reviewed."),
    ("artifacts_verified", "Artifacts verified", "Boot, WIC, BMAP, and SWU artifacts are present."),
    ("flashing_tested", "Flashing tested", "Image was flashed or test evidence was attached."),
    ("dev_origins_confirmed", "Dev origins confirmed", "Linked development builds match the released tag."),
    ("layer_tags_verified", "Layer tags verified", "Required release layer tags are present."),
    ("regression_reviewed", "Regression reviewed", "Latest-vs-previous regression alerts were checked."),
    ("jira_linked", "Jira linked", "Optional release or security tracking ticket is linked."),
]
CHECKLIST_BY_KEY = {key: {"key": key, "label": label, "help": help_text} for key, label, help_text in CHECKLIST}

app = FastAPI(title="NorthFi Release Portal API", version="1.0.0")


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@contextmanager
def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS release_decisions (
                release_key TEXT PRIMARY KEY,
                tag TEXT NOT NULL DEFAULT '',
                build TEXT NOT NULL DEFAULT '',
                machine TEXT NOT NULL DEFAULT '',
                manifest TEXT NOT NULL DEFAULT '',
                commit_sha TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Draft',
                owner TEXT NOT NULL DEFAULT '',
                jira_url TEXT NOT NULL DEFAULT '',
                decision_note TEXT NOT NULL DEFAULT '',
                last_reviewed_at TEXT NOT NULL DEFAULT '',
                updated_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS release_checklist_items (
                release_key TEXT NOT NULL,
                item_key TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                checked INTEGER NOT NULL DEFAULT 0,
                checked_by TEXT NOT NULL DEFAULT '',
                checked_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                PRIMARY KEY (release_key, item_key),
                FOREIGN KEY (release_key) REFERENCES release_decisions(release_key) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS release_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_key TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                field TEXT NOT NULL DEFAULT '',
                old_value TEXT NOT NULL DEFAULT '',
                new_value TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )


@app.on_event("startup")
def on_startup() -> None:
    init_db()


class ReleaseMetadata(BaseModel):
    tag: str = ""
    build: str = ""
    machine: str = ""
    manifest: str = ""
    commit: str = ""


class ReviewUpdate(BaseModel):
    actor: str = Field(default="", max_length=160)
    release: ReleaseMetadata = Field(default_factory=ReleaseMetadata)
    status: str = "Draft"
    owner: str = ""
    jira: str = ""
    note: str = ""
    checks: dict[str, bool] = Field(default_factory=dict)


def clean_status(status: str) -> str:
    return status if status in VALID_STATUSES else "Draft"


def row_to_decision(row: sqlite3.Row | None, release_key: str, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    meta = metadata or {}
    if not row:
        return {
            "release_key": release_key,
            "tag": meta.get("tag", ""),
            "build": meta.get("build", ""),
            "machine": meta.get("machine", ""),
            "manifest": meta.get("manifest", ""),
            "commit": meta.get("commit", ""),
            "status": "Draft",
            "owner": "",
            "jira": "",
            "note": "",
            "last_reviewed_at": "",
            "updated_by": "",
            "updated_at": "",
            "created_at": "",
            "source": "default",
        }
    return {
        "release_key": row["release_key"],
        "tag": row["tag"],
        "build": row["build"],
        "machine": row["machine"],
        "manifest": row["manifest"],
        "commit": row["commit_sha"],
        "status": row["status"],
        "owner": row["owner"],
        "jira": row["jira_url"],
        "note": row["decision_note"],
        "last_reviewed_at": row["last_reviewed_at"],
        "updated_by": row["updated_by"],
        "updated_at": row["updated_at"],
        "created_at": row["created_at"],
        "source": "database",
    }


def checklist_response(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    by_key = {row["item_key"]: row for row in rows}
    response = []
    for key, label, help_text in CHECKLIST:
        row = by_key.get(key)
        response.append({
            "key": key,
            "label": row["label"] if row else label,
            "help": help_text,
            "checked": bool(row["checked"]) if row else False,
            "checked_by": row["checked_by"] if row else "",
            "checked_at": row["checked_at"] if row else "",
            "updated_at": row["updated_at"] if row else "",
        })
    return response


def get_review_payload(conn: sqlite3.Connection, release_key: str, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    decision_row = conn.execute("SELECT * FROM release_decisions WHERE release_key = ?", (release_key,)).fetchone()
    item_rows = conn.execute("SELECT * FROM release_checklist_items WHERE release_key = ?", (release_key,)).fetchall()
    decision = row_to_decision(decision_row, release_key, metadata)
    decision["checklist"] = checklist_response(item_rows)
    return decision


def audit(conn: sqlite3.Connection, release_key: str, actor: str, action: str, field: str = "", old: Any = "", new: Any = "") -> None:
    conn.execute(
        "INSERT INTO release_audit_log (release_key, actor, action, field, old_value, new_value, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (release_key, actor, action, field, "" if old is None else str(old), "" if new is None else str(new), utcnow()),
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "db_path": DB_PATH}


@app.get("/api/reviews")
def list_reviews(status: str | None = None) -> dict[str, Any]:
    with db() as conn:
        params: tuple[Any, ...] = ()
        where = ""
        if status:
            where = "WHERE status = ?"
            params = (status,)
        rows = conn.execute(
            f"SELECT * FROM release_decisions {where} ORDER BY updated_at DESC, created_at DESC",
            params,
        ).fetchall()
        return {"reviews": [row_to_decision(row, row["release_key"]) for row in rows]}


@app.get("/api/reviews/{release_key}")
def get_review(
    release_key: str,
    tag: str = Query(default=""),
    build: str = Query(default=""),
    machine: str = Query(default=""),
    manifest: str = Query(default=""),
    commit: str = Query(default=""),
) -> dict[str, Any]:
    metadata = {"tag": tag, "build": build, "machine": machine, "manifest": manifest, "commit": commit}
    with db() as conn:
        return get_review_payload(conn, release_key, metadata)


@app.put("/api/reviews/{release_key}")
def put_review(release_key: str, payload: ReviewUpdate) -> dict[str, Any]:
    now = utcnow()
    actor = (payload.actor or "").strip()[:160]
    if not actor:
        raise HTTPException(status_code=400, detail="Reviewer name is required")
    status = clean_status(payload.status)
    release = payload.release
    with db() as conn:
        old = conn.execute("SELECT * FROM release_decisions WHERE release_key = ?", (release_key,)).fetchone()
        old_payload = row_to_decision(old, release_key) if old else None
        if old is None:
            conn.execute(
                """
                INSERT INTO release_decisions (
                    release_key, tag, build, machine, manifest, commit_sha, status, owner, jira_url,
                    decision_note, last_reviewed_at, updated_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    release_key, release.tag, release.build, release.machine, release.manifest, release.commit,
                    status, payload.owner, payload.jira, payload.note, now, actor, now, now,
                ),
            )
            audit(conn, release_key, actor, "create_review", "status", "", status)
        else:
            fields = {
                "status": status,
                "owner": payload.owner,
                "jira": payload.jira,
                "note": payload.note,
            }
            for field, new_value in fields.items():
                old_value = old_payload.get(field, "") if old_payload else ""
                if str(old_value or "") != str(new_value or ""):
                    audit(conn, release_key, actor, "update_decision", field, old_value, new_value)
            conn.execute(
                """
                UPDATE release_decisions
                SET tag = ?, build = ?, machine = ?, manifest = ?, commit_sha = ?, status = ?, owner = ?,
                    jira_url = ?, decision_note = ?, last_reviewed_at = ?, updated_by = ?, updated_at = ?
                WHERE release_key = ?
                """,
                (
                    release.tag, release.build, release.machine, release.manifest, release.commit,
                    status, payload.owner, payload.jira, payload.note, now, actor, now, release_key,
                ),
            )

        existing_items = {
            row["item_key"]: row
            for row in conn.execute("SELECT * FROM release_checklist_items WHERE release_key = ?", (release_key,)).fetchall()
        }
        for item_key, checked in payload.checks.items():
            if item_key not in CHECKLIST_BY_KEY:
                continue
            item = CHECKLIST_BY_KEY[item_key]
            checked_int = 1 if checked else 0
            previous = existing_items.get(item_key)
            previous_checked = bool(previous["checked"]) if previous else False
            checked_by = previous["checked_by"] if previous else ""
            checked_at = previous["checked_at"] if previous else ""
            if previous_checked != bool(checked):
                audit(conn, release_key, actor, "update_checklist", item_key, previous_checked, bool(checked))
                checked_by = actor if checked else ""
                checked_at = now if checked else ""
            conn.execute(
                """
                INSERT INTO release_checklist_items (release_key, item_key, label, checked, checked_by, checked_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(release_key, item_key) DO UPDATE SET
                    label = excluded.label,
                    checked = excluded.checked,
                    checked_by = excluded.checked_by,
                    checked_at = excluded.checked_at,
                    updated_at = excluded.updated_at
                """,
                (release_key, item_key, item["label"], checked_int, checked_by, checked_at, now),
            )
        return get_review_payload(conn, release_key)


@app.get("/api/reviews/{release_key}/audit")
def get_audit(release_key: str) -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM release_audit_log WHERE release_key = ? ORDER BY id DESC LIMIT 200",
            (release_key,),
        ).fetchall()
        return {
            "events": [
                {
                    "id": row["id"],
                    "release_key": row["release_key"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "field": row["field"],
                    "old_value": row["old_value"],
                    "new_value": row["new_value"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        }
