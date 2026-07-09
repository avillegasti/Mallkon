# NorthFi Release Dashboard

Local-only dashboard kept in the Yocto workspace but ignored by Git.

Project layout has been refactored into `backend/` and `frontend/` directories.

Data source:

```text
/data/yocto/artifacts/dashboard
```

Run (from repository root):

```bash
docker compose up --build -d
```

Open:

```text
http://localhost:8088
```

Notes:
- Backend code is now under `backend/api/`.
- Indexer script is under `backend/indexer/rebuild-index.py` and is run by the `dashboard-indexer` service.
- Frontend static files are now under `frontend/public/`.
