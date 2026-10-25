"""Modul pivot identitas (lawful).

PENTING — batas desain:
Modul ini TIDAK mengambil, membeli, atau membocorkan data pribadi. Ia hanya:
  1) mengekstrak pengenal yang benar-benar terlihat pada gambar/dokumen,
  2) menyusun tautan ke sumber publik resmi yang boleh dibuka analis,
  3) mencatat kebutuhan dasar hukum sebelum pencarian lebih jauh.

Semua pencarian lanjutan dilakukan manual oleh analis berwenang, dengan jejak audit.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote_plus

# Pengenal yang dapat diekstrak dari teks (OCR) atau diisi analis.
PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone_id": re.compile(r"(?:\+62|62|0)8[1-9][0-9]{6,11}"),
    "phone_intl": re.compile(r"\+(?!62\b)[1-9][0-9]{7,14}"),
    "url": re.compile(r"https?://[^\s<>\"')]+|www\.[^\s<>\"')]+"),
    "handle": re.compile(r"(?<![A-Za-z0-9_.])@[A-Za-z0-9_.]{3,30}"),
    "nik_id": re.compile(r"\b\d{16}\b"),
    "npwp_id": re.compile(r"\b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b"),
    "coordinate": re.compile(r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}"),
    "vehicle_plate_id": re.compile(r"\b[A-Z]{1,2}\s?\d{1,4}\s?[A-Z]{1,3}\b"),
}

# Sumber publik resmi untuk verifikasi identitas korporat/instansi.
PUBLIC_SOURCES: list[dict[str, str]] = [
    {
        "name": "Direktori AHU Kemenkumham",
        "url": "https://ahu.go.id/pencarian/profil",
        "use": "Verifikasi badan hukum & pengurus perusahaan (data publik resmi).",
    },
    {
        "name": "OSS / NIB",
        "url": "https://oss.go.id/",
        "use": "Cek nomor izin usaha bila terlihat pada dokumen.",
    },
    {
        "name": "Pencarian domain WHOIS",
        "url": "https://lookup.icann.org/",
        "use": "Atribusi situs: registrar, tanggal, kontak publik.",
    },
    {
        "name": "Wayback Machine",
        "url": "https://web.archive.org/",
        "use": "Rekam jejak halaman/profil yang sudah dihapus.",
    },
    {
        "name": "GitHub / GitLab publik",
        "url": "https://github.com/search",
        "use": "Email commit, nama, dan afiliasi organisasi pada repositori publik.",
    },
    {
        "name": "OpenCorporates",
        "url": "https://opencorporates.com/",
        "use": "Data perusahaan lintas yurisdiksi.",
    },
    {
        "name": "Arsip berita nasional",
        "url": "https://news.google.com/",
        "use": "Konteks peristiwa & penamaan tokoh dari pemberitaan.",
    },
    {
        "name": "Pangkalan data PBB/WB (entitas)",
        "url": "https://opencorporates.com/",
        "use": "Struktur organisasi internasional.",
    },
]


def _search_links(identifier_type: str, value: str) -> list[dict[str, str]]:
    """Tautan pencarian manual untuk tiap jenis pengenal (tidak ada auto-scraping)."""
    q = quote_plus(value)
    if identifier_type == "email":
        return [
            {"provider": "Pencarian web", "url": f"https://duckduckgo.com/?q=%22{q}%22", "note": "Cari kemunculan publik di forum, dokumen, siaran pers"},
            {"provider": "GitHub", "url": f"https://github.com/search?q={q}&type=users", "note": "Akun & organisasi publik"},
            {"provider": "Have I Been Pwned", "url": f"https://haveibeenpwned.com/account/{q}", "note": "Hanya menunjukkan kebocoran, bukan data pribadi"},
            {"provider": "Google Grup/Mailing list", "url": f"https://www.google.com/search?q=%22{q}%22+site:groups.google.com", "note": "Arsip diskusi publik"},
        ]
    if identifier_type.startswith("phone"):
        return [
            {"provider": "Pencarian web", "url": f"https://duckduckgo.com/?q=%22{q}%22", "note": "Bila nomor muncul di iklan/dokumen publik"},
            {"provider": "Reverse phone publik", "url": f"https://www.google.com/search?q=%22{q}%22+-site:yellowpages.com", "note": "Bukan layanan berbayar penyingkap identitas"},
        ]
    if identifier_type == "url":
        return [
            {"provider": "WHOIS", "url": f"https://lookup.icann.org/en/lookup?q={q}", "note": "Data registrasi domain publik"},
            {"provider": "Wayback", "url": f"https://web.archive.org/web/*/{q}", "note": "Riwayat halaman"},
            {"provider": "Pemeriksa SSL", "url": f"https://crt.sh/?q={q}", "note": "Sertifikat & subdomain publik"},
        ]
    if identifier_type == "handle":
        return [
            {"provider": "Pencarian lintas platform", "url": f"https://instantusername.com/?q={quote_plus(value.lstrip('@'))}", "note": "Cek ketersediaan handle di banyak platform"},
            {"provider": "Pencarian web", "url": f"https://duckduckgo.com/?q=%22{q}%22", "note": "Konteks publik handle"},
        ]
    if identifier_type in {"nik_id", "npwp_id", "vehicle_plate_id"}:
        return [
            {
                "provider": "TIDAK ADA PENCARIAN PUBLIK",
                "url": "",
                "note": "Data identitas & kendaraan hanya dapat diakses instansi berwenang melalui permintaan resmi. Jangan mencoba menembus sistem.",
            }
        ]
    if identifier_type == "coordinate":
        return [
            {"provider": "OpenStreetMap", "url": f"https://www.openstreetmap.org/search?query={q}", "note": "Verifikasi objek di koordinat"},
            {"provider": "SunCalc", "url": "https://www.suncalc.org/", "note": "Cek arah bayangan & waktu"},
        ]
    return [
        {"provider": "Pencarian web", "url": f"https://duckduckgo.com/?q=%22{q}%22", "note": "Pencarian umum"},
    ]


def _mask(value: str) -> str:
    """Sensor sebagian nilai sensitif di keluaran/audit log."""
    if len(value) <= 4:
        return "*" * len(value)
    keep = max(1, len(value) // 4)
    return value[:keep] + "*" * (len(value) - 2 * keep) + value[-keep:]


def extract_identifiers(text: str, extra: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Kumpulkan pengenal dari teks OCR + masukan analis, beserta tautan pivot lawful."""
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, origin: str) -> None:
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        sensitive = kind in {"nik_id", "npwp_id", "phone_id", "phone_intl", "vehicle_plate_id"}
        found.append(
            {
                "type": kind,
                "value": value if not sensitive else _mask(value),
                "masked": sensitive,
                "origin": origin,
                "pivot_links": _search_links(kind, value),
                "legal_gate": (
                    "Butuh dasar hukum / permintaan resmi instansi"
                    if sensitive
                    else "Data publik; tetap catat tujuan penggunaan"
                ),
            }
        )

    for kind, pattern in PATTERNS.items():
        for m in pattern.findall(text or ""):
            add(kind, m.strip(), "OCR gambar")
        for m in pattern.findall(" ".join((extra or {}).values())):
            add(kind, m.strip(), "Masukan analis")

    for field in ("email", "phone", "name", "username", "organization"):
        val = (extra or {}).get(field)
        if val:
            mapped = {
                "email": "email",
                "phone": "phone_intl",
                "name": "person_name",
                "username": "handle",
                "organization": "organization",
            }[field]
            add(mapped, val.strip(), f"Masukan analis ({field})")
    return found


def _person_pivots(name: str) -> list[dict[str, str]]:
    q = quote_plus(name)
    return [
        {"provider": "Pencarian web", "url": f"https://duckduckgo.com/?q=%22{q}%22", "note": "Kemunculan publik nama tersebut"},
        {"provider": "Berita", "url": f"https://news.google.com/search?q=%22{q}%22", "note": "Konteks pemberitaan"},
        {"provider": "LinkedIn publik", "url": f"https://www.linkedin.com/search/results/all/?keywords={q}", "note": "Profil profesional publik"},
        {"provider": "GitHub", "url": f"https://github.com/search?q={q}&type=users", "note": "Akun pengembang publik"},
        {"provider": "ORCID / akademik", "url": f"https://orcid.org/orcid-search/search?searchQuery={q}", "note": "Rekam akademik bila relevan"},
    ]


def _face_search_links() -> list[dict[str, str]]:
    return [
        {"provider": "PimEyes", "url": "https://pimeyes.com/", "note": "Hanya untuk subjek dengan dasar hukum & tujuan sah"},
        {"provider": "FaceCheck.ID", "url": "https://facecheck.id/", "note": "Hasil berupa tautan profil publik; verifikasi manual wajib"},
        {"provider": "Yandex Images", "url": "https://yandex.com/images/", "note": "Pencarian kemiripan wajah gratis"},
        {"provider": "Search4Faces", "url": "https://search4faces.com/", "note": "Terbatas pada platform tertentu"},
    ]


def pivot(analysis: dict[str, Any], extra: dict[str, str] | None = None) -> dict[str, Any]:
    """Susun rencana pivot identitas beserta guardrail dan tingkat keyakinan."""
    ocr_text = (analysis.get("ocr") or {}).get("text", "")
    identifiers = extract_identifiers(ocr_text, extra)

    name = (extra or {}).get("name")
    person_plan = None
    if name:
        person_plan = {
            "subject": name,
            "confidence": 0.35,
            "warning": (
                "Kemiripan nama bukan identitas. Wajib 2+ pengenal independen "
                "(email, akun, organisasi, foto) sebelum menyimpulkan siapa orangnya."
            ),
            "pivot_links": _person_pivots(name),
        }

    face_plan = {
        "note": "Pencarian wajah hanya diizinkan bila ada dasar hukum dan tujuan sah.",
        "gate": "consent_or_legal_basis",
        "engines": _face_search_links(),
    }

    evidence_gaps: list[str] = []
    if not identifiers:
        evidence_gaps.append("Belum ada pengenal terbaca. Perbesar/pertajam area teks lalu ulangi OCR.")
    if not (extra or {}).get("name"):
        evidence_gaps.append("Nama subjek belum diisi; tanpa itu tidak ada pivot identitas.")
    if not analysis.get("exif_present"):
        evidence_gaps.append("Metadata kosong — atribusi perangkat tidak mungkin dari berkas ini.")
    if not analysis.get("gps"):
        evidence_gaps.append("Tanpa GPS, lokasi harus dibuktikan lewat petunjuk visual.")

    return {
        "identifiers": identifiers,
        "identifier_count": len(identifiers),
        "person_plan": person_plan,
        "face_plan": face_plan,
        "public_sources": PUBLIC_SOURCES,
        "evidence_gaps": evidence_gaps,
        "confidence_policy": [
            "0.95 — pengenal langsung dari metadata/dokumen resmi",
            "0.55 — pola kuat (email cocok + akun aktif + organisasi sama)",
            "0.35 — hanya nama atau hanya wajah (indikatif, BUKAN bukti)",
            "0.10 — dugaan berbasis kemiripan tanpa verifikasi",
        ],
        "reporting_rule": (
            "Laporan hanya boleh memuat klaim dengan tingkat keyakinan ≥ 0.55 dan "
            "sumber yang dapat dibuka ulang oleh pihak lain."
        ),
    }
