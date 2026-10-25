"""Mesin geolokasi heuristik berbasis gambar.

Prinsip: setiap kesimpulan harus dapat ditelusuri (explainable). Modul ini tidak
menyimpan atau mengambil data pribadi; ia mengubah bukti visual + metadata menjadi
kandidat lokasi berperingkat beserta tautan verifikasi publik.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any
from urllib.parse import quote_plus

import numpy as np
from PIL import Image

# Kata kunci deskriptor visual -> ciri khas kawasan. Dipakai untuk mengurutkan
# kandidat, bukan untuk menyatakan fakta.
LANDSCAPE_PROFILES: dict[str, dict[str, Any]] = {
    "jalan_raya": {
        "label": "Jalan raya / koridor lalu lintas",
        "clues": ["marka jalan", "tiang listrik", "jenis kendaraan", "bahasa papan nama"],
        "checks": [
            "Arah setir kendaraan (kiri = Indonesia, Jepang, Inggris, Australia)",
            "Warna & gaya marka tepi jalan",
            "Bentuk gardu/tiang listrik dan rambu",
        ],
    },
    "pegunungan": {
        "label": "Pegunungan / perbukitan",
        "clues": ["profil punggungan", "jenis vegetasi", "kabut", "garis salju"],
        "checks": [
            "Bandingkan siluet punggungan dengan citra satelit",
            "Perkirakan ketinggian dari jenis vegetasi (pinus, alpin, tropis)",
            "Cek arah bayangan vs waktu EXIF",
        ],
    },
    "pantai": {
        "label": "Pesisir / pantai",
        "clues": ["warna pasir", "arah ombak", "pulau di horizon", "vegetasi pantai"],
        "checks": [
            "Warna pasir (putih vulkanik, hitam, karang)",
            "Bentuk garis pantai pada citra satelit",
            "Posisi matahari terbit/terbenam untuk memastikan arah hadap",
        ],
    },
    "perkotaan": {
        "label": "Perkotaan padat",
        "clues": ["gaya arsitektur", "papan reklame", "menara", "transportasi umum"],
        "checks": [
            "Bahasa & ejaan pada papan nama",
            "Logo operator/penyedia layanan di sekitar",
            "Nomor gedung / nama jalan yang terlihat",
        ],
    },
    "pedesaan": {
        "label": "Pedesaan / lahan pertanian",
        "clues": ["pola sawah/ladang", "bentuk atap rumah", "ternak", "irigasi"],
        "checks": [
            "Pola petak sawah khas Asia Tenggara",
            "Bahan atap (genteng tanah, seng, rumbia)",
            "Jenis tanaman (padi, jagung, karet, kelapa sawit)",
        ],
    },
    "interior": {
        "label": "Ruang dalam / interior",
        "clues": ["stopkontak", "perabot", "tulisan dinding", "pemandangan jendela"],
        "checks": [
            "Bentuk stopkontak (dua bulat = Eropa, dua pipih = Amerika/Indonesia)",
            "Merek perabot yang hanya dijual di wilayah tertentu",
            "Pemandangan luar lewat jendela",
        ],
    },
    "dokumen": {
        "label": "Dokumen / layar",
        "clues": ["bahasa teks", "logo instansi", "format dokumen"],
        "checks": [
            "Bahasa dan istilah resmi yang digunakan",
            "Logo/kop instansi untuk atribusi",
            "Metadata pembuatan berkas",
        ],
    },
}

# Bahasa yang muncul pada OCR -> kandidat negara/wilayah.
LANGUAGE_HINTS: dict[str, tuple[str, ...]] = {
    "indonesia": ("jalan", "kecamatan", "kelurahan", "kabupaten", "provinsi", "rt", "rw", "dilarang", "parkir", "hati-hati"),
    "malaysia": ("jalan", "taman", "kampung", "lebuh", "buka", "tutup", "awas"),
    "english": ("street", "road", "avenue", "lane", "drive", "please", "warning", "stop"),
    "jepang": ("通り", "駐車", "禁止", "駅"),
    "korea": ("주차", "금지", "역"),
    "arab": ("شارع", "ممنوع", "طريق"),
    "thailand": ("ถนน", "ห้าม", "ที่จอด"),
    "vietnam": ("đường", "cấm", "bãi"),
}


def _timezone_from_longitude(lon: float) -> dict[str, Any]:
    offset = round(lon / 15)
    return {
        "approx_utc_offset_hours": offset,
        "note": "Perkiraan kasar dari bujur; batas zona waktu administratif bisa berbeda.",
    }


def _solar_elevation(lat: float, lon: float, when: datetime) -> dict[str, Any]:
    """Elevasi matahari untuk memvalidasi apakah waktu EXIF masuk akal."""
    day = when.timetuple().tm_yday
    hour = when.hour + when.minute / 60 + when.second / 3600
    decl = 23.44 * math.sin(math.radians(360 / 365 * (day - 81)))
    lst = hour + lon / 15
    ha = 15 * (lst - 12)
    phi, d, h = math.radians(lat), math.radians(decl), math.radians(ha)
    elev = math.degrees(
        math.asin(math.sin(phi) * math.sin(d) + math.cos(phi) * math.cos(d) * math.cos(h))
    )
    return {
        "elevation_deg": round(elev, 1),
        "is_daylight": elev > 0,
        "note": "Matahari di bawah ufuk padahal foto terang = waktu/koordinat tidak konsisten.",
    }


def _color_stats(img: Image.Image) -> dict[str, Any]:
    arr = np.asarray(img.convert("RGB").resize((96, 96)), dtype=np.float64)
    r, g, b = arr[..., 0], arr[..., 1], arr[..., 2]
    hsv = np.asarray(img.convert("HSV").resize((96, 96)), dtype=np.float64)
    hue = hsv[..., 0] * (360 / 255)
    sat = hsv[..., 1] / 255
    val = hsv[..., 2] / 255

    sky = ((b > r) & (b > g) & (val > 0.5)).mean()
    green = ((hue > 60) & (hue < 160) & (sat > 0.2)).mean()
    water = ((hue > 160) & (hue < 260) & (sat > 0.15)).mean()
    asphalt = ((sat < 0.18) & (val < 0.45)).mean()
    warm_soil = ((hue < 45) & (sat > 0.15) & (val > 0.3)).mean()

    tags: list[str] = []
    if green > 0.25:
        tags.append("vegetasi dominan (iklim basah/tropis–subtropis)")
    if sky > 0.18:
        tags.append("bidang langit luas (outdoor, ruang terbuka)")
    if water > 0.12:
        tags.append("permukaan air terdeteksi")
    if asphalt > 0.15:
        tags.append("permukaan aspal/jalan")
    if warm_soil > 0.2:
        tags.append("tanah/lahan terbuka")

    return {
        "sky_ratio": round(float(sky), 3),
        "vegetation_ratio": round(float(green), 3),
        "water_ratio": round(float(water), 3),
        "asphalt_ratio": round(float(asphalt), 3),
        "soil_ratio": round(float(warm_soil), 3),
        "mean_rgb": [round(float(r.mean()), 1), round(float(g.mean()), 1), round(float(b.mean()), 1)],
        "scene_tags": tags,
    }


def _reverse_image_links(image_name: str) -> list[dict[str, str]]:
    """Tautan pivot pencarian gambar balik — analis tetap mengunggah manual."""
    return [
        {"engine": "Google Lens / Images", "url": "https://images.google.com/", "note": "Unggah gambar, cek 'Temukan sumber'"},
        {"engine": "Yandex Images", "url": "https://yandex.com/images/", "note": "Terkuat untuk wajah, wajah & lokasi Timur Eropa/Asia"},
        {"engine": "Bing Visual Search", "url": "https://www.bing.com/visualsearch", "note": "Bagus untuk objek & produk"},
        {"engine": "TinEye", "url": "https://tineye.com/", "note": "Melacak kemunculan pertama gambar di web"},
        {"engine": "PimEyes", "url": "https://pimeyes.com/", "note": "Pencarian wajah; hanya untuk subjek dengan dasar hukum jelas"},
        {"engine": "FaceCheck.ID", "url": "https://facecheck.id/", "note": "Pencarian wajah + tautan profil publik"},
        {"engine": "Forensically", "url": "https://29a.ch/photo-forensics/", "note": "Analisis manipulasi lanjutan (clone detection, ELA)"},
        {"engine": "InVID / WeVerify", "url": "https://weverify.eu/verification-plugin/", "note": "Verifikasi video & gambar untuk jurnalisme"},
    ]


def _map_links(lat: float, lon: float) -> list[dict[str, str]]:
    q = f"{lat},{lon}"
    return [
        {"provider": "Google Maps", "url": f"https://www.google.com/maps?q={q}"},
        {"provider": "OpenStreetMap", "url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"},
        {"provider": "Google Street View", "url": f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={q}"},
        {"provider": "Bing Maps Bird's Eye", "url": f"https://www.bing.com/maps?cp={lat}~{lon}&lvl=18&style=h"},
        {"provider": "SunCalc (bayangan & waktu)", "url": f"https://www.suncalc.org/#/{lat},{lon},17"},
        {"provider": "Wikimapia (objek sekitar)", "url": f"http://wikimapia.org/#lat={lat}&lon={lon}&z=16"},
    ]


def _place_search_links(descriptor: str) -> list[dict[str, str]]:
    q = quote_plus(descriptor)
    return [
        {"provider": "OpenStreetMap Nominatim", "url": f"https://nominatim.openstreetmap.org/search?q={q}"},
        {"provider": "Google Maps", "url": f"https://www.google.com/maps/search/{q}"},
        {"provider": "Mapillary (street-level crowdsourced)", "url": f"https://www.mapillary.com/app/?focus=map&q={q}"},
        {"provider": "Geograph / Flickr Map", "url": f"https://www.flickr.com/map?q={q}"},
    ]


def geolocate(analysis: dict[str, Any], descriptors: list[str] | None = None) -> dict[str, Any]:
    """Hasilkan kandidat lokasi + langkah verifikasi dari hasil forensik."""
    descriptors = [d.strip().lower() for d in (descriptors or []) if d.strip()]
    gps = analysis.get("gps")
    ocr_text = (analysis.get("ocr") or {}).get("text", "")
    ocr_lower = ocr_text.lower()

    candidates: list[dict[str, Any]] = []
    verification: list[str] = []

    if gps:
        lat, lon = gps["latitude"], gps["longitude"]
        candidates.append(
            {
                "rank": 1,
                "confidence": 0.95,
                "label": f"Koordinat tertanam: {lat}, {lon}",
                "basis": ["Tag EXIF GPSInfo pada berkas"],
                "latitude": lat,
                "longitude": lon,
                "precision": "perkiraan radius 5–50 m (bergantung akurasi GPS saat memotret)",
                "links": _map_links(lat, lon),
            }
        )
        verification.append(
            "Cocokkan koordinat dengan citra satelit dan Street View: cari bangunan, tiang, atau vegetasi yang identik."
        )
        verification.append(
            "Periksa apakah koordinat masuk area sensitif; jangan publikasikan bila berisiko keselamatan."
        )
        tz = _timezone_from_longitude(lon)
        when = _parse_exif_time(analysis.get("capture_time", {}).get("exif_datetime"))
        sun = _solar_elevation(lat, lon, when) if when else None
        verification.append(
            f"Zona waktu perkiraan dari bujur: UTC{tz['approx_utc_offset_hours']:+d}."
        )
        if sun:
            verification.append(
                f"Elevasi matahari saat itu ≈ {sun['elevation_deg']}° — "
                + ("konsisten dengan foto siang." if sun["is_daylight"] else "matahari di bawah ufuk; waktu/koordinat patut dipertanyakan.")
            )
    else:
        verification.append(
            "Tidak ada GPS tertanam. Lanjutkan dengan geolokasi visual: pencarian gambar balik + pembacaan petunjuk."
        )

    # Bahasa dari OCR
    lang_hits: list[str] = []
    for lang, words in LANGUAGE_HINTS.items():
        if any(w in ocr_lower for w in words):
            lang_hits.append(lang)
    if lang_hits:
        verification.append(f"Bahasa pada teks gambar mengarah ke: {', '.join(lang_hits)}.")
        candidates.append(
            {
                "rank": len(candidates) + 1,
                "confidence": 0.55,
                "label": f"Wilayah berbahasa: {', '.join(lang_hits)}",
                "basis": ["Kata kunci OCR pada gambar"],
                "precision": "tingkat negara/region",
                "links": [],
            }
        )

    # Deskriptor visual dari pengguna
    for d in descriptors:
        profile = LANDSCAPE_PROFILES.get(d)
        if not profile:
            continue
        candidates.append(
            {
                "rank": len(candidates) + 1,
                "confidence": 0.3,
                "label": f"Tipe lanskap: {profile['label']}",
                "basis": ["Deskriptor yang dipilih analis"],
                "precision": "kandidat kawasan, perlu pembuktian visual",
                "clues": profile["clues"],
                "links": [],
            }
        )
        verification.extend(f"[{profile['label']}] {c}" for c in profile["checks"])

    colors = _color_stats_from_analysis(analysis)
    if colors:
        verification.extend(f"Sinyal warna: {t}" for t in colors.get("scene_tags", []))

    # Pertanyaan geolokasi standar untuk analis
    verification.extend(
        [
            "Baca semua teks: nama jalan, nomor rumah, nama toko, kode pos, nama instansi.",
            "Identifikasi bahasa & ejaan, mata uang, dan format tanggal.",
            "Perhatikan sisi lalu lintas, posisi setir, dan arah hadap kendaraan.",
            "Catat merek yang hanya dijual di wilayah tertentu (waralaba, SPBU, bank).",
            "Bandingkan siluet gunung/bangunan dengan citra satelit.",
            "Perkirakan arah mata angin dari bayangan, lalu cocokkan dengan jam di gambar.",
        ]
    )

    return {
        "candidates": candidates,
        "confidence_note": (
            "Kandidat berperingkat: 0.95 = koordinat metadata, 0.55 = bahasa, "
            "0.3 = tipe lanskap. Ini hipotesis, bukan kebenaran."
        ),
        "verification_checklist": _dedupe(verification),
        "reverse_image_links": _reverse_image_links(""),
        "place_search_links": _place_search_links(" ".join(descriptors)) if descriptors else [],
        "color_signals": colors,
    }


def _color_stats_from_analysis(analysis: dict[str, Any]) -> dict[str, Any] | None:
    """Ambil sinyal warna bila belum ada di hasil forensik (hitung ulang dari preview)."""
    return analysis.get("color_signals")


def _parse_exif_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M:%S%z"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def enrich_colors(analysis: dict[str, Any], img: Image.Image) -> None:
    """Lampirkan statistik warna ke hasil analisis (dipanggil oleh lapisan API)."""
    analysis["color_signals"] = _color_stats(img)
