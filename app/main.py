"""TITIK TERANG — API OSINT gambar yang patuh etika.

Jalankan: uvicorn app.main:app --host 0.0.0.0 --port 12000
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from . import batch, guardrails, report, reverse_search

MAX_UPLOAD_BYTES = int(os.environ.get("OSINT_MAX_UPLOAD_MB", "25")) * 1024 * 1024
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/tiff", "image/bmp", "image/gif"}

app = FastAPI(
    title="TITIK TERANG — OSINT Gambar",
    description=(
        "Platform analisis gambar untuk penegakan hukum, verifikasi jurnalistik, "
        "dan pelatihan keamanan siber. Setiap permintaan melalui gerbang kepatuhan."
    ),
    version="1.0.0",
)

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/api/purposes")
def purposes() -> dict:
    return {
        "purposes": [
            {"id": k, "label": v} for k, v in guardrails.ALLOWED_PURPOSES.items()
        ],
        "descriptors": [
            {"id": k, "label": v["label"]} for k, v in __import__(
                "app.geolocate", fromlist=["LANDSCAPE_PROFILES"]
            ).LANDSCAPE_PROFILES.items()
        ],
    }


@app.get("/api/cases")
def cases(limit: int = 50) -> dict:
    return {"cases": guardrails.list_cases(limit=limit)}


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str) -> dict:
    row = guardrails.get_case(case_id)
    if not row:
        raise HTTPException(status_code=404, detail="Kasus tidak ditemukan")
    return row


@app.post("/api/analyze")
async def analyze(
    image: UploadFile = File(...),
    purpose: str = Form(...),
    attestation: bool = Form(False),
    analyst_name: str = Form(""),
    subject_name: str = Form(""),
    subject_email: str = Form(""),
    subject_phone: str = Form(""),
    subject_username: str = Form(""),
    subject_org: str = Form(""),
    descriptors: str = Form(""),
    note: str = Form(""),
    face_search: bool = Form(False),
) -> JSONResponse:
    data = await image.read()
    if not data:
        raise HTTPException(status_code=400, detail="Berkas kosong")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Berkas melebihi batas {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
        )
    if image.content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Tipe berkas tidak didukung: {image.content_type}",
        )

    payload = {
        "purpose": purpose,
        "attestation": attestation,
        "analyst_name": analyst_name,
        "subject_name": subject_name,
        "subject_email": subject_email,
        "subject_phone": subject_phone,
        "subject_username": subject_username,
        "subject_org": subject_org,
        "descriptors": descriptors,
        "note": note,
        "face_search": face_search,
    }

    try:
        result = report.build_report(data, image.filename or "unnamed", payload)
    except HTTPException:
        raise
    except Exception as exc:  # berkas rusak / bukan gambar
        guardrails.log_audit("analysis_failed", payload, {"allowed": False, "errors": [str(exc)]})
        raise HTTPException(status_code=422, detail=f"Gagal menganalisis gambar: {exc}") from exc

    status = 200 if result["compliance"]["allowed"] else 403
    return JSONResponse(result, status_code=status)


@app.post("/api/report/markdown", response_class=PlainTextResponse)
async def markdown_report(
    image: UploadFile = File(...),
    purpose: str = Form(...),
    attestation: bool = Form(False),
    analyst_name: str = Form(""),
    subject_name: str = Form(""),
    subject_email: str = Form(""),
    subject_phone: str = Form(""),
    subject_username: str = Form(""),
    subject_org: str = Form(""),
    descriptors: str = Form(""),
    note: str = Form(""),
    face_search: bool = Form(False),
) -> PlainTextResponse:
    data = await image.read()
    payload = locals().copy()
    payload.pop("data", None)
    payload.pop("image", None)
    result = report.build_report(data, image.filename or "unnamed", payload)
    return PlainTextResponse(result["markdown"], media_type="text/markdown")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "titik-terang", "version": app.version}


# ---------- Pencarian gambar balik & indeks lokal ----------

@app.post("/api/index")
async def index_image(
    image: UploadFile = File(...),
    label: str = Form(...),
) -> dict:
    data = await image.read()
    if not data:
        raise HTTPException(status_code=400, detail="Berkas kosong")
    return reverse_search.index_image(data, label)


@app.get("/api/index/size")
def index_size() -> dict:
    return {"size": reverse_search.index_size()}


@app.post("/api/similar")
async def similar(
    image: UploadFile = File(...),
    max_distance: int = Form(6),
) -> dict:
    data = await image.read()
    if not data:
        raise HTTPException(status_code=400, detail="Berkas kosong")
    return reverse_search.find_similar(data, max_distance=max_distance)


@app.get("/api/ledger")
def ledger(case_id: str | None = None) -> dict:
    return reverse_search.ledger(case_id)


@app.post("/api/ledger/finding")
def add_finding(
    case_id: str = Form(...),
    engine: str = Form(...),
    result_url: str = Form(...),
    note: str = Form(""),
    confidence: float = Form(0.5),
    analyst: str = Form(""),
) -> dict:
    return reverse_search.record_finding(case_id, engine, result_url, note, confidence, analyst)


@app.get("/api/attribution/{case_id}")
def attribution(case_id: str) -> dict:
    return reverse_search.attribution_chain(case_id)


# ---------- Mode batch ----------

@app.post("/api/batch")
async def batch_analyze(
    images: list[UploadFile] = File(...),
    purpose: str = Form(...),
    attestation: bool = Form(False),
    analyst_name: str = Form(""),
    note: str = Form(""),
) -> JSONResponse:
    if not images:
        raise HTTPException(status_code=400, detail="Tidak ada berkas")
    if len(images) > 200:
        raise HTTPException(status_code=413, detail="Maksimal 200 berkas per batch")

    items: list[tuple[str, bytes]] = []
    for up in images:
        data = await up.read()
        if not data:
            continue
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Berkas {up.filename} melebihi batas {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
            )
        items.append((up.filename or "unnamed", data))

    payload = {
        "purpose": purpose,
        "attestation": attestation,
        "analyst_name": analyst_name,
        "note": note,
    }
    result = batch.analyze_many(items, payload)
    status = 200 if result["compliance"]["allowed"] else 403
    return JSONResponse(result, status_code=status)


@app.post("/api/batch/csv", response_class=PlainTextResponse)
async def batch_csv(
    images: list[UploadFile] = File(...),
    purpose: str = Form(...),
    attestation: bool = Form(False),
    analyst_name: str = Form(""),
    note: str = Form(""),
) -> PlainTextResponse:
    items = []
    for up in images:
        data = await up.read()
        if data:
            items.append((up.filename or "unnamed", data))
    result = batch.analyze_many(
        items,
        {
            "purpose": purpose,
            "attestation": attestation,
            "analyst_name": analyst_name,
            "note": note,
        },
    )
    return PlainTextResponse(batch.to_csv(result), media_type="text/csv")
