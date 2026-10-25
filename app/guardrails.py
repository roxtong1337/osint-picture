"""Guardrail etika & kepatuhan, plus jejak audit.

Setiap permintaan analisis wajib menyertakan tujuan yang sah dan pernyataan
tanggung jawab. Semua aktivitas dicatat ke berkas audit agar dapat diperiksa.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATA_DIR = Path(os.environ.get("OSINT_DATA_DIR", "data"))
AUDIT_FILE = DATA_DIR / "audit.jsonl"
CASE_FILE = DATA_DIR / "cases.jsonl"

# Tujuan yang diizinkan. Di luar daftar ini, permintaan ditolak.
ALLOWED_PURPOSES: dict[str, str] = {
    "penegakan_hukum": "Penyelidikan pidana/penegakan hukum dengan kewenangan resmi.",
    "verifikasi_jurnalistik": "Verifikasi fakta & atribusi sumber oleh jurnalis.",
    "penelitian": "Riset akademik dengan tinjauan etik dan data teranonim.",
    "ctf_pelatihan": "Latihan CTF, kelas, atau pelatihan keamanan siber.",
    "uji_ketahanan_sendiri": "Uji ketahanan (red team) atas aset milik organisasi sendiri.",
    "respons_insiden": "Investigasi insiden siber pada sistem sendiri.",
    "forensik_digital": "Pemeriksaan barang bukti digital yang sah.",
    "perlindungan_anak": "Kasus perlindungan anak / pencarian orang hilang bersama pihak berwenang.",
}

# Pola permintaan yang ditolak: pengawasan tanpa dasar, pelecehan, doxing.
BLOCKED_INTENT_MARKERS = (
    "lacak mantan", "lacak pacar", "stalking", "stocker", "intip orang",
    "doxing", "doxx", "sebar data pribadi", "jual data", "beli data",
    "retas akun", "hack akun", "sadap", "spy pacar", "mata-matai istri",
    "mata-matai suami", "balas dendam",
)

# Wilayah/objek yang tidak boleh dianalisis untuk publikasi.
SENSITIVE_TARGET_MARKERS = (
    "markas", "kodam", "pangkalan militer", "bandara militer", "vip",
    "pos jaga", "gudang senjata", "kantor bareskrim", "data center nasional",
)


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append(path: Path, record: dict[str, Any]) -> None:
    ensure_dirs()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def screen_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Periksa tujuan, pernyataan, dan niat sebelum analisis dijalankan."""
    purpose = (payload.get("purpose") or "").strip()
    attestation = bool(payload.get("attestation"))
    free_text = " ".join(
        str(payload.get(k, "")) for k in ("note", "subject_name", "descriptors", "purpose_detail")
    ).lower()

    errors: list[str] = []
    warnings: list[str] = []

    if purpose not in ALLOWED_PURPOSES:
        errors.append(
            "Tujuan tidak sah atau tidak dipilih. Pilih salah satu tujuan yang diizinkan."
        )
    if not attestation:
        errors.append(
            "Pernyataan tanggung jawab belum dicentang: analis menyatakan memiliki dasar "
            "hukum/dasar sah dan tidak akan menggunakan hasil untuk mengawasi orang tanpa izin."
        )
    if any(m in free_text for m in BLOCKED_INTENT_MARKERS):
        errors.append(
            "Permintaan mengandung indikasi pengawasan tanpa dasar (stalking/doxing/akses ilegal). Ditolak."
        )
    if any(m in free_text for m in SENSITIVE_TARGET_MARKERS):
        warnings.append(
            "Terdeteksi kemungkinan target sensitif. Hasil hanya untuk kanal internal "
            "berwenang; dilarang dipublikasikan."
        )
    if payload.get("face_search") and purpose not in {"penegakan_hukum", "perlindungan_anak", "forensik_digital"}:
        warnings.append(
            "Pencarian wajah umumnya butuh dasar hukum kuat; untuk tujuan ini sebaiknya "
            "gunakan pencarian gambar balik biasa."
        )

    return {
        "allowed": not errors,
        "errors": errors,
        "warnings": warnings,
        "purpose": purpose,
        "purpose_description": ALLOWED_PURPOSES.get(purpose),
        "checked_at": _now(),
    }


def log_audit(event: str, payload: dict[str, Any], decision: dict[str, Any] | None = None) -> str:
    """Catat peristiwa ke jejak audit (append-only, JSONL)."""
    ref = uuid.uuid4().hex[:12]
    _append(
        AUDIT_FILE,
        {
            "ref": ref,
            "event": event,
            "at": _now(),
            "actor": payload.get("analyst_name") or "anonim",
            "purpose": payload.get("purpose"),
            "allowed": (decision or {}).get("allowed"),
            "errors": (decision or {}).get("errors", []),
            "subject_hash": payload.get("image_sha256"),
            "face_search": bool(payload.get("face_search")),
        },
    )
    return ref


def save_case(case: dict[str, Any]) -> str:
    """Simpan ringkasan kasus (tanpa gambar) untuk penelusuran & laporan."""
    case_id = uuid.uuid4().hex[:12]
    record = {"case_id": case_id, "created_at": _now(), **case}
    _append(CASE_FILE, record)
    return case_id


def list_cases(limit: int = 50) -> list[dict[str, Any]]:
    ensure_dirs()
    if not CASE_FILE.exists():
        return []
    rows: list[dict[str, Any]] = []
    with CASE_FILE.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows[-limit:][::-1]


def get_case(case_id: str) -> dict[str, Any] | None:
    for row in list_cases(limit=1000):
        if row.get("case_id") == case_id:
            return row
    return None


def chain_of_custody(image_sha256: str, actor: str, purpose: str) -> dict[str, Any]:
    """Catatan rantai bukti minimal: hash, aktor, tujuan, waktu."""
    return {
        "evidence_sha256": image_sha256,
        "handled_by": actor or "anonim",
        "purpose": purpose,
        "acquired_at": _now(),
        "integrity_note": (
            "Berkas tidak pernah dimodifikasi oleh alat ini. Bandingkan hash sebelum "
            "dan sesudah pemeriksaan untuk membuktikan keutuhan barang bukti."
        ),
    }
