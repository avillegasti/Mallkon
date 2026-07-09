import json
import os
import shutil
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from jose import JWTError, jwt
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:release_password_secure@db:5432/release_portal")
KEYCLOAK_ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://keycloak:8080/realms/northfi")
ARTIFACT_ROOT = Path(os.environ.get("ARTIFACT_ROOT", "/artifacts"))
DASHBOARD_DATA_DIR = Path(os.environ.get("DASHBOARD_DATA_DIR", "/artifacts/dashboard"))
KEYCLOAK_AUDIENCE = os.environ.get("KEYCLOAK_AUDIENCE", "release-dashboard")
JWKS_CACHE: dict[str, Any] = {"keys": [], "fetched_at": 0}
JWKS_TTL_SECONDS = 300
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

DB_POOL = None

def get_db_pool():
    global DB_POOL
    if DB_POOL is None:
        DB_POOL = SimpleConnectionPool(1, 20, dsn=DATABASE_URL)
    return DB_POOL


class DbCursorWrapper:
    def __init__(self, cur):
        self.cur = cur

    def fetchone(self):
        return self.cur.fetchone()

    def fetchall(self):
        return self.cur.fetchall()

    def __iter__(self):
        return iter(self.cur)


class DbConnectionWrapper:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql: str, params: tuple = ()):
        # Convert sqlite ? placeholder to postgres %s
        sql = sql.replace('?', '%s')
        cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(sql, params)
        return DbCursorWrapper(cur)

    def executescript(self, sql: str):
        cur = self.conn.cursor()
        cur.execute(sql)
        return DbCursorWrapper(cur)


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@contextmanager
def db() -> DbConnectionWrapper:
    pool = get_db_pool()
    conn = pool.getconn()
    try:
        wrapper = DbConnectionWrapper(conn)
        yield wrapper
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def init_db() -> None:
    # Wait for database connection to be ready (useful during docker container startup)
    retries = 5
    while retries > 0:
        try:
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
                        id SERIAL PRIMARY KEY,
                        release_key TEXT NOT NULL,
                        actor TEXT NOT NULL DEFAULT '',
                        action TEXT NOT NULL,
                        field TEXT NOT NULL DEFAULT '',
                        old_value TEXT NOT NULL DEFAULT '',
                        new_value TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS user_profiles (
                        user_sub TEXT PRIMARY KEY,
                        jira_token TEXT NOT NULL DEFAULT ''
                    );
                    """
                )
            break
        except psycopg2.OperationalError as exc:
            print(f"Database connection failed, retrying... ({retries} left). Error: {exc}", flush=True)
            time.sleep(2)
            retries -= 1


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


def fetch_jwks() -> list[dict[str, Any]]:
    global JWKS_CACHE
    now = time.time()
    if JWKS_CACHE["keys"] and now - JWKS_CACHE["fetched_at"] < JWKS_TTL_SECONDS:
        return JWKS_CACHE["keys"]

    try:
        response = requests.get(f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs", timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail=f"Could not load Keycloak JWKS: {exc}")

    JWKS_CACHE = {"keys": data.get("keys", []), "fetched_at": now}
    return JWKS_CACHE["keys"]


def get_public_jwk(kid: str) -> dict[str, Any] | None:
    for key in fetch_jwks():
        if key.get("kid") == kid:
            return key
    return None


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header")

    token = authorization.split(" ", 1)[1].strip()
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Invalid token header")

        key = get_public_jwk(kid)
        if not key:
            raise HTTPException(status_code=401, detail="Unknown token key")

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_iss": False, "verify_aud": False},
        )
        # Verify issuer manually. Allow any valid URL pointing to the 'northfi' realm.
        iss = payload.get("iss", "")
        if not (iss.startswith("http://") or iss.startswith("https://")) or not iss.endswith("/realms/northfi"):
            raise JWTError(f"Invalid issuer: {iss}")

        # Verify audience or authorized party (azp)
        aud = payload.get("aud", "")
        azp = payload.get("azp", "")
        auds = aud if isinstance(aud, list) else [aud] if aud else []
        if KEYCLOAK_AUDIENCE not in auds and azp != KEYCLOAK_AUDIENCE:
            raise JWTError(f"Invalid audience or authorized party: aud={aud}, azp={azp}")
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")
    groups = [g.lstrip("/") for g in payload.get("groups", [])] if isinstance(payload.get("groups"), list) else []
    return {
        "username": payload.get("preferred_username", ""),
        "email": payload.get("email", ""),
        "sub": payload.get("sub", ""),
        "roles": list(set(
            (payload.get("realm_access", {}).get("roles", []) if isinstance(payload.get("realm_access"), dict) else []) +
            (payload.get("resource_access", {}).get(KEYCLOAK_AUDIENCE, {}).get("roles", []) if isinstance(payload.get("resource_access"), dict) else []) +
            groups
        )),
    }


def audit(conn: sqlite3.Connection, release_key: str, actor: str, action: str, field: str = "", old: Any = "", new: Any = "") -> None:
    conn.execute(
        "INSERT INTO release_audit_log (release_key, actor, action, field, old_value, new_value, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (release_key, actor, action, field, "" if old is None else str(old), "" if new is None else str(new), utcnow()),
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "db_path": DB_PATH}


@app.get("/api/reviews")
def list_reviews(status: str | None = None, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
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
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    metadata = {"tag": tag, "build": build, "machine": machine, "manifest": manifest, "commit": commit}
    with db() as conn:
        return get_review_payload(conn, release_key, metadata)


@app.put("/api/reviews/{release_key}")
def put_review(release_key: str, payload: ReviewUpdate, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    user_roles = current_user.get("roles", [])
    if "admin" not in user_roles and "approver" not in user_roles:
        raise HTTPException(status_code=403, detail="Permission denied: Only admin or approver roles can modify release reviews")
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
def get_audit(release_key: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
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


@app.delete("/api/builds/{build_id}")
def delete_build(build_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    # 1. Enforce admin permission
    user_roles = current_user.get("roles", [])
    if "admin" not in user_roles:
        raise HTTPException(status_code=403, detail="Permission denied: Only admin role can delete builds")

    # 2. Determine group and source_id from build_id
    if build_id.startswith("releases-"):
        group = "releases"
        source_id = build_id[len("releases-"):]
    elif build_id.startswith("development-"):
        group = "development"
        source_id = build_id[len("development-"):]
    else:
        raise HTTPException(status_code=400, detail="Invalid build ID format")

    # 3. Locate extracted metadata directory
    metadata_dir = DASHBOARD_DATA_DIR / group / source_id
    if not metadata_dir.exists():
        raise HTTPException(status_code=404, detail="Build metadata not found")

    # 4. Read source_archive path from release.json (if exists)
    release_json_path = metadata_dir / "release.json"
    source_archive_path = None
    if release_json_path.exists():
        try:
            with open(release_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                source_archive_path = data.get("metadata", {}).get("source_archive")
        except Exception as exc:
            print(f"Error reading release.json: {exc}", flush=True)

    # 5. Delete the source archive parent directory (safely within ARTIFACT_ROOT)
    if source_archive_path:
        archive_path = Path(source_archive_path)
        target_dir = archive_path.parent
        try:
            resolved_root = ARTIFACT_ROOT.resolve()
            resolved_target = target_dir.resolve()
            
            if resolved_target != resolved_root and resolved_root in resolved_target.parents:
                # Check for sibling images directory (replace 'yocto-metadata-' with 'yocto-images-')
                if resolved_target.name.startswith("yocto-metadata-"):
                    images_dir_name = resolved_target.name.replace("yocto-metadata-", "yocto-images-", 1)
                    images_dir = resolved_target.parent / images_dir_name
                    try:
                        resolved_images = images_dir.resolve()
                        if resolved_images != resolved_root and resolved_root in resolved_images.parents:
                            if resolved_images.exists():
                                shutil.rmtree(resolved_images)
                                print(f"Deleted sibling images directory: {resolved_images}", flush=True)
                    except Exception as exc:
                        print(f"Error deleting sibling images directory: {exc}", flush=True)

                if resolved_target.exists():
                    shutil.rmtree(resolved_target)
                    print(f"Deleted source archive directory: {resolved_target}", flush=True)
            else:
                resolved_file = archive_path.resolve()
                if resolved_file.exists() and resolved_root in resolved_file.parents:
                    resolved_file.unlink()
                    print(f"Deleted source archive file: {resolved_file}", flush=True)
        except Exception as exc:
            print(f"Error deleting source archive: {exc}", flush=True)

    # 6. Delete extracted metadata directory
    try:
        shutil.rmtree(metadata_dir)
        print(f"Deleted metadata directory: {metadata_dir}", flush=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete metadata directory: {exc}")

    # 7. Delete corresponding entry from local DB release decisions
    try:
        with db() as conn:
            conn.execute("DELETE FROM release_decisions WHERE build = ?", (source_id,))
    except Exception as exc:
        print(f"Error deleting release decisions from DB: {exc}", flush=True)

    # 8. Rebuild the index so frontend updates immediately
    try:
        rebuild_script = "/app/scripts/rebuild-index.py"
        if os.path.exists(rebuild_script):
            subprocess.run(["python3", rebuild_script], check=True)
            print("Successfully ran rebuild-index.py", flush=True)
        else:
            print(f"Rebuild script not found at {rebuild_script}", flush=True)
    except Exception as exc:
        print(f"Error running rebuild-index.py: {exc}", flush=True)

    return {"status": "ok", "message": f"Build {build_id} successfully deleted"}


class ProfileUpdate(BaseModel):
    jira_token: str = ""


@app.get("/api/profile")
def get_profile(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT jira_token FROM user_profiles WHERE user_sub = ?", (current_user["sub"],)).fetchone()
        jira_token = row["jira_token"] if row else ""
        return {"jira_token": jira_token}


@app.put("/api/profile")
def put_profile(payload: ProfileUpdate, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO user_profiles (user_sub, jira_token) VALUES (?, ?)
            ON CONFLICT(user_sub) DO UPDATE SET jira_token = excluded.jira_token
            """,
            (current_user["sub"], payload.jira_token),
        )
        return {"status": "ok", "jira_token": payload.jira_token}


