"""Mode batch: analisis banyak gambar sekaligus untuk kampanye kesadaran digital.

Kasus pakai utama: satuan mengunggah ratusan foto prajurit untuk mengukur berapa
persen yang masih membawa koordinat GPS, lalu memakai hasilnya sebagai dasar
pelatihan keamanan digital.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import forensics, guardrails, verify


def analyze_many(
    items: Iterable[tuple[str, bytes]],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Analisis kumpulan gambar. Mengembalikan statistik agregat + baris per berkas.

    items: pasangan (nama berkas, isi berkas).
    """
    payload = payload or {}
    decision = guardrails.screen_request(payload)
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for name, data in items:
        try:
            a = forensics.analyze(data)
        except Exception as exc:
            errors.append({"file": name, "error": str(exc)})
            continue
        v = verify.verify(data, a)
        rows.append(
            {
                "file": name,
                "sha256": a["file"]["sha256"],
                "format": a["file"]["format"],
                "megapixels": a["file"]["megapixels"],
                "gps_present": bool(a.get("gps")),
                "latitude": (a.get("gps") or {}).get("latitude"),
                "longitude": (a.get("gps") or {}).get("longitude"),
                "device": a["device"].get("model") or a["device"].get("make") or "-",
                "device_class": a["device"]["device_class"],
                "exif_present": a["exif_present"],
                "exif_tags": len(a["exif"]),
                "software": a["device"].get("software") or "-",
                "ocr_chars": len((a.get("ocr") or {}).get("text", "")),
                "ela_verdict": a["ela"]["verdict"],
                "risk_score": a["risk_score"]["score"],
                "risk_band": a["risk_score"]["band"],
                "authenticity_score": v["authenticity_score"],
                "authenticity_band": v["authenticity_band"],
                "likely_origin": v["platform_origin"]["likely_origin"],
                "ai_likelihood": v["ai_generation"]["ai_likelihood"],
            }
        )

    audit_ref = guardrails.log_audit(
        "batch_analysis",
        {**payload, "image_sha256": f"batch:{len(rows)}"},
        decision,
    )

    if decision["allowed"]:
        guardrails.save_case(
            {
                "file_name": f"batch:{len(rows)} berkas",
                "sha256": f"batch-{audit_ref}",
                "purpose": payload.get("purpose"),
                "analyst_name": payload.get("analyst_name"),
                "audit_ref": audit_ref,
                "risk_score": _avg(r["risk_score"] for r in rows),
                "gps_present": any(r["gps_present"] for r in rows),
                "identifier_count": 0,
                "summary": {"batch": True, "count": len(rows)},
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_ref": audit_ref,
        "compliance": decision,
        "count": len(rows),
        "errors": errors,
        "aggregate": _aggregate(rows),
        "rows": rows,
        "recommendations": _recommendations(rows),
    }


def _avg(values: Iterable[float]) -> float:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 1) if vals else 0.0


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"count": 0}
    total = len(rows)
    gps = sum(1 for r in rows if r["gps_present"])
    exif = sum(1 for r in rows if r["exif_present"])
    edited = sum(1 for r in rows if "penyuntingan" in r["ela_verdict"] or "tinggi" in r["ela_verdict"])
    ai = sum(1 for r in rows if r["ai_likelihood"] >= 0.6)
    devices = Counter(r["device"] for r in rows if r["device"] != "-")
    software = Counter(r["software"] for r in rows if r["software"] != "-")
    bands = Counter(r["risk_band"] for r in rows)
    return {
        "count": total,
        "gps_present": gps,
        "gps_ratio": round(gps / total, 3),
        "exif_present": exif,
        "exif_ratio": round(exif / total, 3),
        "possibly_edited": edited,
        "ai_suspected": ai,
        "avg_risk_score": _avg(r["risk_score"] for r in rows),
        "avg_authenticity": _avg(r["authenticity_score"] for r in rows),
        "risk_bands": dict(bands),
        "top_devices": devices.most_common(5),
        "top_software": software.most_common(5),
    }


def _recommendations(rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return []
    agg = _aggregate(rows)
    out: list[str] = []
    if agg["gps_ratio"] > 0.3:
        out.append(
            f"{agg['gps_present']} dari {agg['count']} foto ({agg['gps_ratio']*100:.0f}%) masih memuat koordinat GPS. "
            "Wajib ada prosedur penghapusan metadata sebelum unggah."
        )
    if agg["exif_ratio"] > 0.5:
        out.append(
            "Mayoritas foto mempertahankan metadata perangkat. Aktifkan penghapusan lokasi pada kamera ponsel dinas."
        )
    if agg["possibly_edited"]:
        out.append(f"{agg['possibly_edited']} foto menunjukkan indikasi penyuntingan — telusuri siapa yang menyunting dan mengapa.")
    if agg["ai_suspected"]:
        out.append(f"{agg['ai_suspected']} foto berindikasi dihasilkan AI — perlu kebijakan verifikasi untuk dokumen visual.")
    if not out:
        out.append("Tidak ada masalah metadata yang menonjol pada kumpulan ini. Pertahankan kebiasaan baik.")
    return out


def to_csv(report: dict[str, Any]) -> str:
    """Ekspor hasil batch ke CSV untuk lampiran laporan."""
    buf = io.StringIO()
    fields = [
        "file", "sha256", "format", "megapixels", "gps_present", "latitude", "longitude",
        "device", "device_class", "exif_present", "exif_tags", "software", "ocr_chars",
        "ela_verdict", "risk_score", "risk_band", "authenticity_score",
        "authenticity_band", "likely_origin", "ai_likelihood",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in report["rows"]:
        writer.writerow(row)
    return buf.getvalue()


def analyze_folder(folder: str | Path, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Analisis semua gambar dalam sebuah folder."""
    path = Path(folder)
    exts = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp", ".gif"}
    items = [
        (p.name, p.read_bytes())
        for p in sorted(path.iterdir())
        if p.is_file() and p.suffix.lower() in exts
    ]
    return analyze_many(items, payload)
