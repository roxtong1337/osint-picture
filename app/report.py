"""Perakit laporan akhir: menyatukan forensik, geolokasi, dan pivot identitas."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from PIL import Image

from . import forensics, geolocate, guardrails, identity, media_forensics, reverse_search, verify


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
    verification = verify.verify(image_bytes, analysis)
    pivot = reverse_search.pivot_bundle(image_bytes, analysis)
    media = media_forensics.full_media_report(image_bytes) if payload.get("media_analysis", True) else None

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
        "summary": _summary(analysis, geo, ident, decision, verification, media),
        "forensics": analysis,
        "verification": verification,
        "media_forensics": media,
        "geolocation": geo,
        "identity_pivot": ident,
        "reverse_search": pivot,
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
                "authenticity_score": verification["authenticity_score"],
                "gps_present": bool(analysis.get("gps")),
                "identifier_count": ident["identifier_count"],
                "summary": report["summary"],
            }
        )
        report["case_id"] = case_id
        if payload.get("index_image", True):
            entry = reverse_search.index_image(image_bytes, f"{filename}#{case_id}", analysis)
            report["indexed_as"] = entry["entry_id"]

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


def _summary(
    analysis: dict, geo: dict, ident: dict, decision: dict, verification: dict, media: dict | None = None
) -> dict[str, Any]:
    gps = analysis.get("gps")
    media = media or {}
    faces = media.get("faces") or {}
    anomalies = media.get("face_anomalies") or {}
    deepfake = media.get("deepfake") or {}
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
        "authenticity_score": verification["authenticity_score"],
        "authenticity_band": verification["authenticity_band"],
        "likely_origin": verification["platform_origin"]["likely_origin"],
        "ai_likelihood": verification["ai_generation"]["ai_likelihood"],
        "faces_detected": faces.get("count", 0),
        "face_anomaly_band": anomalies.get("band", "TIDAK DAPAT DINILAI"),
        "deepfake_band": deepfake.get("band", "TIDAK DAPAT DINILAI"),
        "deepfake_score": deepfake.get("score", 0.0),
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
    add(f"- Skor autentisitas: {s['authenticity_score']}/100 ({s['authenticity_band']})")
    add(f"- Perkiraan asal unggahan: {s['likely_origin']}")
    add(f"- Indikasi media AI: {s['ai_likelihood']}")
    add(f"- Wajah terdeteksi: {s.get('faces_detected', 0)}")
    add(f"- Anomali wajah: {s.get('face_anomaly_band', '-')}")
    add(f"- Indikasi deepfake: {s.get('deepfake_band', '-')} ({s.get('deepfake_score', 0)})")
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

    add("## 2. Verifikasi Autentisitas")
    add("")
    v = report["verification"]
    add(f"- Skor autentisitas: {v['authenticity_score']}/100 ({v['authenticity_band']})")
    add(f"- Interpretasi: {v['interpretation']}")
    add(f"- Riwayat kompresi: {v['compression_history']['compression_level']}")
    add(f"- Kualitas JPEG perkiraan: {v['compression_history']['estimated_jpeg_quality']}")
    for sig in v["compression_history"]["signals"]:
        add(f"  - {sig}")
    add(f"- Perkiraan asal: {v['platform_origin']['likely_origin']} (keyakinan {v['platform_origin']['confidence']})")
    for cand in v["platform_origin"]["candidates"]:
        add(f"  - {cand['platform']} — {cand['basis']} ({cand['confidence']})")
    ai = v["ai_generation"]
    add(f"- Indikasi media generatif: {ai['ai_likelihood']} ({ai['band']})")
    for sig in ai["signals"]:
        add(f"  - {sig}")
    for note in v["score_notes"]:
        add(f"- Penalti skor: {note}")
    add("")

    add("## 3. Rencana Pencarian Gambar Balik")
    add("")
    rs = report["reverse_search"]
    for step in rs["pivot_plan"]["steps"]:
        add(f"{step['step']}. **{step['action']}** — {step['why']}")
        add(f"   - Tautan: {step['url']}")
        add(f"   - Catat: {step['record']}")
    add("")
    li = rs["local_index"]
    add(f"- Indeks lokal: {li['size']} gambar, {li['match_count']} kemiripan ditemukan")
    for m in li["matches"]:
        add(f"  - `{m['label']}` — {m['verdict']} (jarak rata-rata {m['combined_distance']})")
    add(f"- {li['interpretation']}")
    add("")

    add("## 4. Geolokasi")
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

    media = report.get("media_forensics")
    if media:
        add("## 5. Analisis Media & Deteksi Manipulasi")
        add("")
        faces = media["faces"]
        anom = media["face_anomalies"]
        df = media["deepfake"]
        traces = media["social_media_traces"]
        add(f"Wajah terdeteksi: **{faces.get('count', 0)}** · anomali wajah: **{anom.get('band')}** · "
            f"indikasi deepfake: **{df.get('band')}** ({df.get('score')})")
        add("")
        if faces.get("count"):
            add("| Wajah | Kotak (x,y,w,h) | Ketajaman | Derau | Kecerahan | Kecurigaan |")
            add("| --- | --- | --- | --- | --- | --- |")
            for f in faces["faces"]:
                b = f["box"]
                finding = next((x for x in anom.get("findings", []) if x["face_index"] == f["index"]), None)
                susp = finding["suspicion"] if finding else 0
                add(f"| {f['index']} | {b['x']},{b['y']},{b['w']},{b['h']} | {f['sharpness']} | "
                    f"{f['noise_sigma']} | {f['brightness']} | {susp} |")
            add("")
        for finding in anom.get("findings", []):
            if finding["signals"]:
                add(f"**Wajah {finding['face_index']}** — kecurigaan {finding['suspicion']} ({finding['band']}):")
                for sig in finding["signals"]:
                    add(f"- {sig}")
                add("")
        if df.get("signals"):
            add("Sinyal deepfake:")
            for sig in df["signals"]:
                add(f"- {sig}")
            add("")
        if traces.get("traces"):
            add(f"Jejak antarmuka: {traces['interpretation']}")
            for t in traces["traces"]:
                add(f"- {t['signal']} → {t['implication']} (keyakinan {t['confidence']})")
            add("")
        add(f"> {anom.get('method_note', '')}")
        add(f"> {df.get('caveat', '')}")
        add(f"> {media.get('scope', '')}")
        add("")

    add("## 6. Pivot Identitas")
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

    add("## 7. Kepatuhan & Rantai Bukti")
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
