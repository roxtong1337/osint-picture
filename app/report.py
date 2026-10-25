"""Perakit laporan akhir: menyatukan forensik, geolokasi, dan pivot identitas."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from PIL import Image

from . import forensics, geolocate, guardrails, identity


def build_report(
    image_bytes: bytes,
    filename: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Jalankan pipeline lengkap dan kembalikan laporan terstruktur."""
    decision = guardrails.screen_request(payload)

    analysis = forensics.analyze(image_bytes)
    img = Image.open(io.BytesIO(image_bytes))
    geolocate.enrich_colors(analysis, img)

    descriptors = _as_list(payload.get("descriptors"))
    extra = {
        "email": payload.get("subject_email") or "",
        "phone": payload.get("subject_phone") or "",
        "name": payload.get("subject_name") or "",
        "username": payload.get("subject_username") or "",
        "organization": payload.get("subject_org") or "",
    }

    geo = geolocate.geolocate(analysis, descriptors)
    ident = identity.pivot(analysis, extra)

    custody = guardrails.chain_of_custody(
        analysis["file"]["sha256"], payload.get("analyst_name", ""), payload.get("purpose", "")
    )
    audit_ref = guardrails.log_audit("analysis", {**payload, "image_sha256": analysis["file"]["sha256"]}, decision)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_ref": audit_ref,
        "file_name": filename,
        "compliance": decision,
        "chain_of_custody": custody,
        "summary": _summary(analysis, geo, ident, decision),
        "forensics": analysis,
        "geolocation": geo,
        "identity_pivot": ident,
        "disclaimer": (
            "Hasil ini adalah hipotesis analitis, bukan putusan. Setiap klaim wajib "
            "diverifikasi ulang dengan sumber independen. Penggunaan untuk mengawasi "
            "orang tanpa dasar hukum adalah pelanggaran dan akan tercatat di jejak audit."
        ),
    }

    if decision["allowed"]:
        case_id = guardrails.save_case(
            {
                "file_name": filename,
                "sha256": analysis["file"]["sha256"],
                "purpose": payload.get("purpose"),
                "analyst_name": payload.get("analyst_name"),
                "audit_ref": audit_ref,
                "risk_score": analysis["risk_score"]["score"],
                "gps_present": bool(analysis.get("gps")),
                "identifier_count": ident["identifier_count"],
                "summary": report["summary"],
            }
        )
        report["case_id"] = case_id

    report["markdown"] = to_markdown(report)
    return report


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v for v in (x.strip() for x in value.split(",")) if v]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _summary(analysis: dict, geo: dict, ident: dict, decision: dict) -> dict[str, Any]:
    gps = analysis.get("gps")
    return {
        "compliance_ok": decision["allowed"],
        "location_headline": (
            f"GPS tertanam: {gps['latitude']}, {gps['longitude']}"
            if gps
            else "Tidak ada GPS tertanam — lokasi harus dibuktikan lewat petunjuk visual"
        ),
        "candidate_locations": len(geo["candidates"]),
        "identifiers_found": ident["identifier_count"],
        "device": analysis["device"].get("model") or analysis["device"].get("device_class"),
        "risk_score": analysis["risk_score"]["score"],
        "risk_band": analysis["risk_score"]["band"],
        "next_action": (
            "Jalankan pencarian gambar balik, lalu verifikasi kandidat lokasi di peta."
            if not gps
            else "Validasi koordinat di peta & Street View, lalu periksa arah bayangan."
        ),
    }


def to_markdown(report: dict[str, Any]) -> str:
    """Ekspor laporan ke Markdown untuk lampiran proposal/dokumentasi."""
    f = report["forensics"]
    s = report["summary"]
    lines: list[str] = []
    add = lines.append

    add("# Laporan Analisis OSINT Gambar")
    add("")
    add(f"- Dibuat: {report['generated_at']}")
    add(f"- Berkas: `{report['file_name']}`")
    add(f"- SHA-256: `{f['file']['sha256']}`")
    add(f"- Referensi audit: `{report['audit_ref']}`")
    if report.get("case_id"):
        add(f"- ID kasus: `{report['case_id']}`")
    add(f"- Kepatuhan: {'LOLOS' if s['compliance_ok'] else 'DITOLAK'}")
    add("")

    add("## Ringkasan")
    add("")
    add(f"- {s['location_headline']}")
    add(f"- Kandidat lokasi: {s['candidate_locations']}")
    add(f"- Pengenal ditemukan: {s['identifiers_found']}")
    add(f"- Perangkat: {s['device']}")
    add(f"- Skor risiko kebocoran: {s['risk_score']}/100 ({s['risk_band']})")
    add(f"- Langkah berikutnya: {s['next_action']}")
    add("")

    add("## 1. Forensik Berkas")
    add("")
    add("| Atribut | Nilai |")
    add("| --- | --- |")
    add(f"| Format | {f['file']['format']} |")
    add(f"| Dimensi | {f['file']['width']}x{f['file']['height']} px |")
    add(f"| Ukuran | {f['file']['size_bytes']} byte |")
    add(f"| MD5 | `{f['file']['md5']}` |")
    add(f"| SHA-1 | `{f['file']['sha1']}` |")
    add(f"| SHA-256 | `{f['file']['sha256']}` |")
    add("")

    add("### Perangkat & Sinyal Anti-Forensik")
    add("")
    d = f["device"]
    add(f"- Make/Model: {d.get('make')} / {d.get('model')}")
    add(f"- Lensa: {d.get('lens')}")
    add(f"- Kelas perangkat: {d['device_class']}")
    for sig in d["counter_forensic_signals"]:
        add(f"- {sig}")
    add("")

    add("### Analisis Manipulasi (ELA)")
    add("")
    ela = f["ela"]
    add(f"- Rata-rata galat: {ela['mean_error']} | Std: {ela['std_error']} | P99: {ela['p99_error']}")
    add(f"- Kesimpulan: {ela['verdict']}")
    add("")

    add("### OCR")
    add("")
    ocr = f["ocr"]
    if ocr.get("available") and ocr.get("text"):
        add("```")
        add(ocr["text"])
        add("```")
    else:
        add(f"Tidak tersedia: {ocr.get('reason', 'tidak ada teks')}")
    add("")

    add("## 2. Geolokasi")
    add("")
    for c in report["geolocation"]["candidates"]:
        add(f"### Kandidat {c['rank']} — {c['label']}")
        add("")
        add(f"- Keyakinan: {c['confidence']}")
        add(f"- Dasar: {', '.join(c['basis'])}")
        add(f"- Presisi: {c['precision']}")
        for lnk in c.get("links", []):
            provider = lnk.get("provider") or lnk.get("engine")
            add(f"- [{provider}]({lnk['url']})")
        add("")
    if not report["geolocation"]["candidates"]:
        add("Belum ada kandidat. Isi deskriptor lanskap dan lengkapi petunjuk visual.")
        add("")

    add("### Daftar Periksa Verifikasi")
    add("")
    for item in report["geolocation"]["verification_checklist"]:
        add(f"- [ ] {item}")
    add("")

    add("## 3. Pivot Identitas")
    add("")
    ip = report["identity_pivot"]
    if ip["identifiers"]:
        add("| Jenis | Nilai | Asal | Gerbang Legal |")
        add("| --- | --- | --- | --- |")
        for i in ip["identifiers"]:
            add(f"| {i['type']} | `{i['value']}` | {i['origin']} | {i['legal_gate']} |")
    else:
        add("Tidak ada pengenal terbaca.")
    add("")
    for gap in ip["evidence_gaps"]:
        add(f"- Kekurangan bukti: {gap}")
    add("")

    add("## 4. Kepatuhan & Rantai Bukti")
    add("")
    c = report["compliance"]
    add(f"- Tujuan: {c.get('purpose')} — {c.get('purpose_description')}")
    add(f"- Diizinkan: {c['allowed']}")
    for e in c["errors"]:
        add(f"- Pelanggaran: {e}")
    for w in c["warnings"]:
        add(f"- Peringatan: {w}")
    add("")
    add(f"> {report['disclaimer']}")
    return "\n".join(lines)
