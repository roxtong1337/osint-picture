"""Verifikasi autentisitas & asal platform gambar.

Menjawab pertanyaan: apakah gambar ini asli dari kamera, pernah dikompres ulang,
hasil suntingan, atau dihasilkan AI? Dan dari platform mana gambar ini berasal?

Semua penilaian bersifat indikatif. Tidak ada satu metode pun yang cukup untuk
menyimpulkan manipulasi; kesimpulan diambil dari gabungan sinyal.
"""

from __future__ import annotations

import io
import math
from typing import Any

import numpy as np
from PIL import Image, ImageChops

from . import forensics

# Dimensi/rasio khas hasil unggah platform sosial (dimensi sisi terpanjang).
PLATFORM_SIGNATURES: dict[str, dict[str, Any]] = {
    "whatsapp": {
        "dims": {(1600, 1200), (1280, 960), (800, 600), (1600, 1600), (1200, 1600)},
        "note": "WhatsApp membatasi sisi panjang ~1600 px dan menghapus seluruh EXIF.",
        "exif_expectation": "kosong",
    },
    "instagram": {
        "dims": {(1080, 1080), (1080, 1350), (1080, 566), (1080, 608), (1440, 1440)},
        "note": "Instagram menormalkan ke lebar 1080 px dan menyisipkan tag 'Instagram'.",
        "exif_expectation": "sebagian",
    },
    "facebook": {
        "dims": {(960, 720), (2048, 1152), (720, 720), (960, 960)},
        "note": "Facebook sering menyisakan Software 'Facebook' atau membuat EXIF minimal.",
        "exif_expectation": "sebagian",
    },
    "telegram": {
        "dims": {(1280, 1280), (2560, 1440)},
        "note": "Telegram mempertahankan metadata kecuali mode kompresi dipilih.",
        "exif_expectation": "utuh",
    },
    "twitter_x": {
        "dims": {(1200, 675), (1600, 900), (2048, 1152)},
        "note": "X/Twitter menghapus metadata lokasi namun menyisakan sebagian EXIF.",
        "exif_expectation": "sebagian",
    },
    "screenshot": {
        "dims": set(),
        "note": "Tangkapan layar: EXIF kosong, sering berisi bilah status.",
        "exif_expectation": "kosong",
    },
}

# Penanda kuat bahwa berkas dibuat/disimpan perangkat tertentu.
DEVICE_SOFTWARE_MARKERS: dict[str, str] = {
    "instagram": "Berkas diekspor Instagram",
    "whatsapp": "Berkas diekspor WhatsApp",
    "facebook": "Berkas diekspor Facebook",
    "snapchat": "Berkas diekspor Snapchat",
    "tiktok": "Berkas diekspor TikTok",
    "screenshot": "Tangkapan layar perangkat",
    "google": "Berkas dari layanan Google (Photos/Drive)",
    "apple": "Berkas dari ekosistem Apple (Photos/Preview)",
    "samsung": "Tangkapan layar/layanan Samsung",
    "xiaomi": "Perangkat Xiaomi/MIUI",
}


def _recompression_estimate(img: Image.Image, analysis: dict[str, Any]) -> dict[str, Any]:
    """Perkirakan riwayat kompresi ulang dari kualitas & residu.

    Gambar yang dikompres ulang pada kualitas rendah menunjukkan galat ELA besar
    namun blok DCT yang rapi. Kualitas tinggi berulang menunjukkan galat kecil
    dengan tekstur halus.
    """
    ela = analysis["ela"]
    jpeg_sig = analysis.get("jpeg_signature")
    quality_estimate = None
    if jpeg_sig and jpeg_sig.get("tables", {}).get("table_0"):
        table = jpeg_sig["tables"]["table_0"]
        # Perkiraan kasar kualitas dari rata-rata koefisien kuantisasi.
        mean_q = float(np.mean(table)) if table else 0
        if mean_q <= 2:
            quality_estimate = 95
        elif mean_q <= 4:
            quality_estimate = 85
        elif mean_q <= 8:
            quality_estimate = 75
        elif mean_q <= 16:
            quality_estimate = 60
        elif mean_q <= 32:
            quality_estimate = 45
        else:
            quality_estimate = 30

    arr = np.asarray(img.convert("L").resize((256, 256)), dtype=np.float64)
    block_noise = float(np.mean(np.abs(np.diff(arr, axis=1))))
    high_freq_ratio = float(
        np.mean(np.abs(np.diff(arr, axis=0)) > 12)
    )

    signals: list[str] = []
    level = "tidak jelas"
    if ela["mean_error"] < 1.0 and block_noise < 3.0:
        level = "satu kali kompresi (kemungkinan asli kamera)"
        signals.append("Residu ELA rendah merata — sesuai satu kali kompresi JPEG.")
    elif ela["mean_error"] < 3.5:
        level = "kemungkinan satu kali kompresi dengan mutu sedang"
        signals.append("Residu rendah tapi terlihat — mutu ekspor sedang.")
    elif high_freq_ratio > 0.35:
        level = "indikasi kompresi ulang berlapis"
        signals.append("Tekstur frekuensi tinggi tinggi — khas kompresi berulang.")
    else:
        level = "indikasi penyuntingan atau kompresi ulang berat"
        signals.append("Residu ELA tinggi tidak merata — indikasi penyuntingan lokal.")

    return {
        "estimated_jpeg_quality": quality_estimate,
        "compression_level": level,
        "signals": signals,
        "block_noise": round(block_noise, 3),
        "high_freq_ratio": round(high_freq_ratio, 3),
    }


def _platform_origin(img: Image.Image, analysis: dict[str, Any]) -> dict[str, Any]:
    """Tebak asal platform dari dimensi, EXIF, dan penanda perangkat lunak."""
    exif = analysis.get("exif", {})
    software = str(exif.get("Software") or "").lower()
    make = str(exif.get("Make") or "").lower()
    dims = (img.width, img.height)
    long_side = max(dims)

    matches: list[dict[str, Any]] = []

    for name, marker in DEVICE_SOFTWARE_MARKERS.items():
        if name in software:
            matches.append({"platform": name, "confidence": 0.9, "basis": f"Tag Software memuat '{marker}'"})
        elif name in make:
            matches.append({"platform": name, "confidence": 0.6, "basis": f"Make perangkat '{marker}'"})

    for name, sig in PLATFORM_SIGNATURES.items():
        if sig["dims"] and dims in sig["dims"]:
            matches.append(
                {"platform": name, "confidence": 0.65, "basis": f"Dimensi {dims[0]}×{dims[1]} cocok pola {name}"}
            )
        elif name == "whatsapp" and long_side == 1600 and not analysis.get("exif_present"):
            matches.append(
                {"platform": "whatsapp", "confidence": 0.75, "basis": "Sisi panjang 1600 px + EXIF kosong"}
            )

    if not analysis.get("exif_present"):
        matches.append(
            {
                "platform": "platform sosial / screenshot",
                "confidence": 0.5,
                "basis": "EXIF kosong — hampir semua platform sosial menghapus metadata",
            }
        )

    # Rapikan: ambil keyakinan tertinggi per platform
    best: dict[str, dict[str, Any]] = {}
    for m in matches:
        cur = best.get(m["platform"])
        if not cur or m["confidence"] > cur["confidence"]:
            best[m["platform"]] = m
    ranked = sorted(best.values(), key=lambda x: -x["confidence"])

    return {
        "likely_origin": ranked[0]["platform"] if ranked else "tidak dapat ditentukan",
        "confidence": ranked[0]["confidence"] if ranked else 0.0,
        "candidates": ranked[:5],
        "note": (
            "Perkiraan ini memakai dimensi & metadata. Kesimpulan pasti hanya dari "
            "perbandingan dengan berkas asli sebelum diunggah."
        ),
    }


def _ai_generation_indicators(img: Image.Image, analysis: dict[str, Any]) -> dict[str, Any]:
    """Sinyal indikatif gambar dihasilkan model generatif."""
    exif = analysis.get("exif", {})
    software = str(exif.get("Software") or "").lower()
    signals: list[str] = []
    score = 0.0

    if any(k in software for k in forensics.GENERATIVE_SOFTWARE):
        score += 0.6
        signals.append(f"Penanda perangkat lunak generatif: {exif.get('Software')}")

    # C1: konsistensi noise — gambar AI sering terlalu bersih pada area datar.
    arr = np.asarray(img.convert("L"), dtype=np.float64)
    if arr.size:
        flat_mask = np.abs(np.diff(arr, axis=1)) < 2
        flat_ratio = float(flat_mask.mean())
        if flat_ratio > 0.75:
            score += 0.15
            signals.append("Area datar sangat dominan tanpa noise sensor — khas render/AI.")
        # Noise sensor naik dengan ISO; gambar AI biasanya tidak punya pola ini.
        if analysis["device"]["capture"].get("iso") and flat_ratio > 0.7:
            signals.append("ISO tinggi tapi area datar tanpa noise — tidak konsisten dengan sensor kamera.")

    if not analysis.get("exif_present"):
        signals.append("Tanpa metadata kamera (juga umum pada media generatif & unggahan ulang).")

    score = min(score, 1.0)
    return {
        "ai_likelihood": round(score, 2),
        "band": "TINGGI" if score >= 0.6 else "SEDANG" if score >= 0.3 else "RENDAH",
        "signals": signals,
        "caveat": (
            "Tidak ada detektor AI yang dapat dipercaya penuh. Angka ini indikatif; "
            "untuk keputusan hukum gunakan pemeriksaan forensik laboratorium."
        ),
    }


def _geometry_consistency(img: Image.Image) -> dict[str, Any]:
    """Cek dasar geometri: apakah gambar punya petunjuk struktur alami."""
    arr = np.asarray(img.convert("RGB").resize((320, 320)), dtype=np.float64)
    gray = arr.mean(axis=2)
    gx = np.abs(np.diff(gray, axis=1)).mean()
    gy = np.abs(np.diff(gray, axis=0)).mean()
    ratio = float(gx / gy) if gy else 0.0
    return {
        "horizontal_gradient": round(float(gx), 3),
        "vertical_gradient": round(float(gy), 3),
        "gradient_ratio": round(ratio, 3),
        "note": (
            "Rasio jauh dari 1 menandakan orientasi/metadata rotasi perlu diperiksa "
            "(banyak kamera menyimpan orientasi tanpa memutar piksel)."
        ),
    }


def verify(image_bytes: bytes, analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """Jalankan verifikasi autentisitas lengkap."""
    analysis = analysis or forensics.analyze(image_bytes)
    img = Image.open(io.BytesIO(image_bytes))
    img.load()

    recompress = _recompression_estimate(img, analysis)
    platform = _platform_origin(img, analysis)
    ai = _ai_generation_indicators(img, analysis)
    geometry = _geometry_consistency(img)

    # Skor autentisitas 0-100: makin tinggi, makin meyakinkan gambar asli.
    authenticity = 100.0
    notes: list[str] = []
    if not analysis.get("exif_present"):
        authenticity -= 25
        notes.append("EXIF kosong (−25)")
    if not analysis.get("gps"):
        authenticity -= 10
        notes.append("Tanpa GPS (−10)")
    if "penyuntingan" in recompress["compression_level"] or "berlapis" in recompress["compression_level"]:
        authenticity -= 25
        notes.append("Indikasi kompresi ulang/penyuntingan (−25)")
    if analysis["device"]["counter_forensic_signals"]:
        authenticity -= 10
        notes.append("Sinyal anti-forensik terdeteksi (−10)")
    if ai["ai_likelihood"] >= 0.6:
        authenticity -= 30
        notes.append("Indikasi kuat media generatif (−30)")
    elif ai["ai_likelihood"] >= 0.3:
        authenticity -= 15
        notes.append("Indikasi sedang media generatif (−15)")
    if analysis["ela"]["mean_error"] > 5:
        authenticity -= 10
        notes.append("Residu ELA tinggi (−10)")

    authenticity = max(0.0, min(100.0, authenticity))
    return {
        "authenticity_score": round(authenticity, 1),
        "authenticity_band": (
            "TINGGI" if authenticity >= 75 else "SEDANG" if authenticity >= 50
            else "RENDAH" if authenticity >= 30 else "SANGAT RENDAH"
        ),
        "score_notes": notes,
        "compression_history": recompress,
        "platform_origin": platform,
        "ai_generation": ai,
        "geometry": geometry,
        "interpretation": _interpret(authenticity, platform, ai),
    }


def _interpret(score: float, platform: dict[str, Any], ai: dict[str, Any]) -> str:
    if ai["ai_likelihood"] >= 0.6:
        return "Gambar berindikasi kuat dihasilkan/dimodifikasi AI. Jangan dipakai sebagai bukti tanpa pemeriksaan laboratorium."
    if score >= 75:
        return "Metadata dan residu konsisten dengan foto kamera yang wajar. Tetap verifikasi konteks peristiwanya."
    if score >= 50:
        origin = platform["likely_origin"]
        return (
            f"Gambar tampak berasal dari {origin}. Asal unggahan jelas, namun "
            "keaslian isi perlu diverifikasi lewat sumber lain."
        )
    return "Bukti lemah: metadata hilang dan ada indikasi manipulasi. Cari berkas asli atau saksi independen."
