"""Alur kerja pencarian gambar balik + indeks hash perseptual lokal.

Dua kemampuan:

1. **Indeks lokal.** Gambar yang pernah dianalisis disimpan sebagai hash perseptual
   (aHash/dHash/pHash). Analisis berikutnya bisa mencari kemiripan **tanpa internet** —
   berguna untuk mendeteksi gambar hoaks yang dipakai ulang, atau membandingkan
   barang bukti dengan arsip yang sudah ada.

2. **Buku kerja pivot.** Mesin pencarian balik melarang akses program, jadi alat ini
   menyiapkan rencana langkah + URL siap buka, lalu mencatat temuan analis ke buku
   kerja. Semua temuan menjadi rantai atribusi yang dapat diperiksa ulang.
"""

from __future__ import annotations

import io
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import forensics, geolocate, guardrails

INDEX_FILE = guardrails.DATA_DIR / "hash_index.jsonl"
LEDGER_FILE = guardrails.DATA_DIR / "search_ledger.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    guardrails.ensure_dirs()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def hamming(a: str, b: str) -> int:
    """Jarak Hamming antara dua bitstring hash perseptual."""
    if not a or not b or len(a) != len(b):
        return max(len(a), len(b))
    return sum(1 for x, y in zip(a, b) if x != y)


def _detail_level(image_bytes: bytes) -> float:
    """Ukur seberapa banyak struktur pada gambar (0 = rata, 1 = sangat detail).

    Hash perseptual tidak dapat diandalkan pada gambar nyaris rata (langit polos,
    warna solid). Nilai ini dipakai untuk menandai hasil yang perlu diragukan.
    """
    import numpy as np
    from PIL import Image

    img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((128, 128))
    arr = np.asarray(img, dtype=np.float64)
    grad = (np.abs(np.diff(arr, axis=0)).mean() + np.abs(np.diff(arr, axis=1)).mean()) / 2
    return round(min(grad / 12.0, 1.0), 3)


def index_image(image_bytes: bytes, label: str, analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """Tambahkan gambar ke indeks hash lokal. Berkas identik tidak diduplikasi."""
    analysis = analysis or forensics.analyze(image_bytes)
    sha = analysis["file"]["sha256"]

    for entry in _read_jsonl(INDEX_FILE):
        if entry.get("sha256") == sha:
            return {**entry, "already_indexed": True}

    entry = {
        "entry_id": uuid.uuid4().hex[:12],
        "label": label,
        "sha256": sha,
        "hashes": analysis["hashes_perceptual"],
        "detail_level": _detail_level(image_bytes),
        "width": analysis["file"]["width"],
        "height": analysis["file"]["height"],
        "indexed_at": _now(),
        "already_indexed": False,
    }
    _append_jsonl(INDEX_FILE, entry)
    return entry


def index_size() -> int:
    return len(_read_jsonl(INDEX_FILE))


def find_similar(
    image_bytes: bytes,
    max_distance: int = 6,
    analysis: dict[str, Any] | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Cari gambar mirip di indeks lokal berdasarkan hash perseptual.

    Ambang jarak: 0 = identik secara persepsi, ≤6 = sangat mirip (kemungkinan
    kompresi ulang/crop ringan), >10 biasanya gambar berbeda.
    """
    analysis = analysis or forensics.analyze(image_bytes)
    target = analysis["hashes_perceptual"]
    target_sha = analysis["file"]["sha256"]
    target_detail = _detail_level(image_bytes)
    matches: list[dict[str, Any]] = []

    for entry in _read_jsonl(INDEX_FILE):
        hs = entry.get("hashes") or {}
        entry_detail = entry.get("detail_level")
        distances = {
            "ahash": hamming(target["ahash"], hs.get("ahash", "")),
            "dhash": hamming(target["dhash"], hs.get("dhash", "")),
            "phash": hamming(target["phash"], hs.get("phash", "")),
        }
        # pHash paling andal untuk gambar datar; aHash mudah memberi positif palsu.
        # Karena itu penilaian memakai dHash & pHash, aHash hanya pelengkap.
        primary = min(distances["dhash"], distances["phash"])
        combined = round((distances["dhash"] + distances["phash"]) / 2, 2)
        exact = entry["sha256"] == target_sha

        # Gambar nyaris rata (mis. warna solid) menghasilkan hash acak yang bisa
        # tampak "identik". Tandai sebagai tidak andal alih-alih melaporkan cocok.
        low_detail = target_detail < 0.05 or (entry_detail is not None and entry_detail < 0.05)
        if low_detail and not exact:
            continue

        if exact or primary <= max_distance:
            matches.append(
                {
                    "entry_id": entry["entry_id"],
                    "label": entry["label"],
                    "sha256_match": exact,
                    "distances": distances,
                    "combined_distance": combined,
                    "verdict": _verdict(distances, exact),
                    "indexed_at": entry["indexed_at"],
                }
            )

    matches.sort(key=lambda m: (not m["sha256_match"], m["combined_distance"]))
    unreliable = target_detail < 0.05
    interpretation = (
        "Tidak ada kemiripan di indeks lokal."
        if not matches
        else f"Ditemukan {len(matches)} gambar mirip. Periksa apakah ini gambar yang sama dengan versi berbeda."
    )
    if unreliable:
        interpretation = (
            "Gambar nyaris rata (tanpa detail) sehingga pencocokan hash perseptual tidak dapat "
            "diandalkan. Hasil kemiripan diabaikan; gunakan hash berkas untuk identifikasi."
        )
    return {
        "index_size": index_size(),
        "max_distance": max_distance,
        "detail_level": target_detail,
        "reliable": not unreliable,
        "match_count": len(matches),
        "matches": matches[:limit],
        "interpretation": interpretation,
    }


def _verdict(distances: dict[str, int], exact_hash: bool) -> str:
    if exact_hash:
        return "SAMA PERSIS (hash berkas identik)"
    best = min(distances["dhash"], distances["phash"])
    if best <= 2:
        return "sangat mirip — kemungkinan besar gambar yang sama"
    if best <= 6:
        return "mirip — kemungkinan versi hasil kompresi/crop ringan"
    return "kemungkinan berbeda"


def pivot_plan(analysis: dict[str, Any]) -> dict[str, Any]:
    """Susun rencana pencarian gambar balik berurutan, siap dijalankan analis."""
    has_gps = bool(analysis.get("gps"))
    has_text = bool((analysis.get("ocr") or {}).get("text"))
    steps: list[dict[str, Any]] = [
        {
            "step": 1,
            "action": "Unggah ke TinEye",
            "why": "Melacak kemunculan paling awal gambar di web — menentukan siapa yang mengunggah lebih dulu.",
            "engine": "TinEye",
            "url": "https://tineye.com/",
            "record": "Catat tanggal kemunculan paling awal + URL sumber pertama.",
        },
        {
            "step": 2,
            "action": "Unggah ke Google Lens / Images",
            "why": "Menemukan halaman serupa dan 'temukan sumber' untuk versi beresolusi lebih tinggi.",
            "engine": "Google",
            "url": "https://images.google.com/",
            "record": "Catat situs yang memuat gambar + apakah resolusi lebih tinggi.",
        },
        {
            "step": 3,
            "action": "Unggah ke Yandex Images",
            "why": "Terkuat untuk lokasi geografis dan wajah; sering menemukan versi dari media lain.",
            "engine": "Yandex",
            "url": "https://yandex.com/images/",
            "record": "Catat hasil 'mirip' dan 'situs yang memuat'.",
        },
        {
            "step": 4,
            "action": "Unggah ke Bing Visual Search",
            "why": "Baik untuk objek, produk, dan landmark.",
            "engine": "Bing",
            "url": "https://www.bing.com/visualsearch",
            "record": "Catat halaman sumber objek/landmark yang cocok.",
        },
    ]
    if has_text:
        steps.append(
            {
                "step": 5,
                "action": "Cari teks hasil OCR di mesin pencari",
                "why": "Teks pada gambar (nama jalan, instansi) sering langsung menunjuk lokasi/konteks.",
                "engine": "Pencarian teks",
                "url": "https://duckduckgo.com/",
                "record": "Catat teks yang menghasilkan kecocokan.",
            }
        )
    if has_gps:
        steps.append(
            {
                "step": len(steps) + 1,
                "action": "Validasi koordinat di peta & Street View",
                "why": "Buktikan lokasi dengan objek fisik yang terlihat pada gambar.",
                "engine": "Peta",
                "url": "https://www.google.com/maps",
                "record": "Catat objek pembanding yang identik (bangunan, tiang, vegetasi).",
            }
        )

    return {
        "steps": steps,
        "recorded_findings_required": True,
        "ethics_note": (
            "Unggah manual oleh analis. Jangan mengotomatiskan pengambilan data dari mesin "
            "pencarian — melanggar ketentuan layanan dan berisiko hukum."
        ),
    }


def record_finding(
    case_id: str,
    engine: str,
    result_url: str,
    note: str = "",
    confidence: float = 0.5,
    analyst: str = "",
) -> dict[str, Any]:
    """Catat temuan pencarian ke buku kerja."""
    if not 0.0 <= confidence <= 1.0:
        confidence = max(0.0, min(1.0, confidence))
    finding = {
        "finding_id": uuid.uuid4().hex[:12],
        "case_id": case_id,
        "engine": engine,
        "result_url": result_url,
        "note": note,
        "confidence": round(confidence, 2),
        "analyst": analyst or "anonim",
        "recorded_at": _now(),
    }
    _append_jsonl(LEDGER_FILE, finding)
    return finding


def ledger(case_id: str | None = None) -> dict[str, Any]:
    rows = _read_jsonl(LEDGER_FILE)
    if case_id:
        rows = [r for r in rows if r.get("case_id") == case_id]
    return {"count": len(rows), "findings": rows[::-1][:100]}


def attribution_chain(case_id: str) -> dict[str, Any]:
    """Rangkum temuan menjadi rantai atribusi + nilai kelayakan laporan."""
    findings = ledger(case_id)["findings"]
    engines = sorted({f["engine"] for f in findings})
    strongest = max((f["confidence"] for f in findings), default=0.0)
    independent_sources = len(engines)

    if independent_sources >= 2 and strongest >= 0.55:
        verdict = "SIAP DILAPORKAN"
        reason = "Ada ≥2 sumber independen dan minimal satu temuan berkekuatan tinggi."
    elif findings:
        verdict = "BELUM CUKUP"
        reason = "Temuan ada, tetapi sumber independen atau tingkat keyakinan belum memadai."
    else:
        verdict = "BELUM ADA TEMUAN"
        reason = "Belum ada temuan tercatat di buku kerja untuk kasus ini."

    return {
        "case_id": case_id,
        "finding_count": len(findings),
        "independent_sources": independent_sources,
        "engines": engines,
        "strongest_confidence": strongest,
        "verdict": verdict,
        "reason": reason,
        "rule": "Aturan pelaporan: ≥2 sumber independen + keyakinan ≥0.55.",
    }


def pivot_bundle(image_bytes: bytes, analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """Paket lengkap untuk UI: indeks, kemiripan lokal, rencana, mesin, tautan peta."""
    analysis = analysis or forensics.analyze(image_bytes)
    similar = find_similar(image_bytes, analysis=analysis)
    geo = analysis.get("gps")
    return {
        "pivot_plan": pivot_plan(analysis),
        "local_index": {
            "size": similar["index_size"],
            "match_count": similar["match_count"],
            "matches": similar["matches"],
            "interpretation": similar["interpretation"],
        },
        "engines": geolocate._reverse_image_links(""),
        "map_links": geolocate._map_links(geo["latitude"], geo["longitude"]) if geo else [],
        "face_engines": [
            {"provider": "PimEyes", "url": "https://pimeyes.com/", "note": "Dasar hukum kuat wajib"},
            {"provider": "FaceCheck.ID", "url": "https://facecheck.id/", "note": "Verifikasi manual wajib"},
            {"provider": "Yandex Images", "url": "https://yandex.com/images/", "note": "Kemiripan wajah gratis"},
        ],
    }
