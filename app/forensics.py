"""Inti forensik gambar: metadata EXIF, GPS, hash, fingerprint perangkat, dan sinyal manipulasi.

Modul ini hanya membaca properti teknis berkas gambar. Tidak ada data yang dikirim
ke luar proses kecuali diminta eksplisit oleh pemanggil (lihat geolocate/identity).
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from typing import Any

import numpy as np
from PIL import ExifTags, Image, ImageChops

Image.MAX_IMAGE_PIXELS = 120_000_000

# Perangkat lunak yang menandakan gambar pernah disunting / diekspor ulang.
EDITING_SOFTWARE = (
    "photoshop", "gimp", "lightroom", "snapseed", "picsart", "canva",
    "affinity", "pixlr", "inkscape", "capture one", "darktable", "paint.net",
    "screenshot", "snip", "greenshot", "sharex", "imagemagick", "preview",
)

# Perangkat lunak yang menandakan gambar dihasilkan/di-generate, bukan difoto.
GENERATIVE_SOFTWARE = (
    "midjourney", "stable diffusion", "dall", "firefly", "flux", "comfyui",
    "automatic1111", "invokeai", "generative",
)


def _sha(data: bytes, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def _to_float(value: Any) -> float | None:
    """Konversi nilai rasional EXIF (atau tuple) menjadi float."""
    try:
        if value is None:
            return None
        if isinstance(value, tuple) and len(value) == 2:
            num, den = value
            if den == 0:
                return None
            return float(num) / float(den)
        if hasattr(value, "numerator") and hasattr(value, "denominator"):
            if value.denominator == 0:
                return None
            return float(value.numerator) / float(value.denominator)
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _gps_to_decimal(coord: Any, ref: Any) -> float | None:
    """Ubah (derajat, menit, detik) EXIF GPS menjadi derajat desimal."""
    try:
        deg, minutes, seconds = (coord + (0.0,) * 3)[:3]
        dec = (_to_float(deg) or 0.0) + (_to_float(minutes) or 0.0) / 60 + (
            _to_float(seconds) or 0.0
        ) / 3600
        if isinstance(ref, str) and ref.upper() in {"S", "W"}:
            dec = -dec
        return round(dec, 7)
    except (TypeError, ValueError, IndexError):
        return None


def _decode_exif(img: Image.Image) -> dict[str, Any]:
    """Baca seluruh tag EXIF termasuk sub-IFD GPS dan Exif."""
    out: dict[str, Any] = {}
    try:
        exif = img.getexif()
    except Exception:
        return out

    for tag_id, value in exif.items():
        name = ExifTags.TAGS.get(tag_id, f"Tag{tag_id}")
        out[name] = _clean(value)

    for ifd_name in ("Exif", "GPSInfo", "Interop", "MakerNote"):
        try:
            ifd = exif.get_ifd(getattr(ExifTags.IFD, ifd_name))
        except Exception:
            continue
        if not ifd:
            continue
        table = ExifTags.GPSTAGS if ifd_name == "GPSInfo" else ExifTags.TAGS
        for tag_id, value in ifd.items():
            name = table.get(tag_id, f"Tag{tag_id}")
            out[f"{ifd_name}.{name}"] = _clean(value)
    return out


def _clean(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            return value.hex()
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, (int, float, str)):
        return value
    return str(value)


def _extract_gps(exif: dict[str, Any]) -> dict[str, Any] | None:
    lat_raw = exif.get("GPSInfo.GPSLatitude")
    lon_raw = exif.get("GPSInfo.GPSLongitude")
    if not lat_raw or not lon_raw:
        return None
    lat = _gps_to_decimal(tuple(lat_raw), exif.get("GPSInfo.GPSLatitudeRef"))
    lon = _gps_to_decimal(tuple(lon_raw), exif.get("GPSInfo.GPSLongitudeRef"))
    if lat is None or lon is None:
        return None
    altitude = _to_float(exif.get("GPSInfo.GPSAltitude"))
    return {
        "latitude": lat,
        "longitude": lon,
        "altitude_m": round(altitude, 1) if altitude is not None else None,
        "timestamp_utc": exif.get("GPSInfo.GPSTimeStamp"),
        "datum": exif.get("GPSInfo.GPSMapDatum", "WGS-84"),
        "source": "exif_gps",
        "precision": "koordinat perangkat (dapat digeser/di-spoof)",
    }


def _device_fingerprint(exif: dict[str, Any]) -> dict[str, Any]:
    make = exif.get("Make")
    model = exif.get("Model")
    lens = exif.get("Exif.LensModel") or exif.get("LensModel")
    software = exif.get("Software")
    serial = exif.get("Exif.BodySerialNumber") or exif.get("BodySerialNumber")
    lens_serial = exif.get("Exif.LensSerialNumber")
    iso = exif.get("Exif.ISOSpeedRatings") or exif.get("ISOSpeedRatings")
    fnum = _to_float(exif.get("Exif.FNumber"))
    exposure = _to_float(exif.get("Exif.ExposureTime"))
    focal = _to_float(exif.get("Exif.FocalLength"))
    orientation = exif.get("Orientation")

    device_class = "tidak diketahui"
    if make or model:
        device_class = "kamera / ponsel (metadata utuh)"
    elif exif:
        device_class = "metadata terbatas (kemungkinan hasil ekspor/scrub)"
    else:
        device_class = "tanpa metadata (kemungkinan dihapus atau dari platform sosial)"

    soft_lower = str(software).lower() if software else ""
    signals: list[str] = []
    if any(s in soft_lower for s in EDITING_SOFTWARE):
        signals.append(f"Perangkat lunak penyunting terdeteksi: {software}")
    if any(s in soft_lower for s in GENERATIVE_SOFTWARE):
        signals.append(f"Penanda media generatif/AI terdeteksi: {software}")
    if not exif:
        signals.append("Metadata EXIF kosong — umum pada gambar dari WhatsApp/Instagram.")
    if make and not model:
        signals.append("Make ada tanpa Model — metadata kemungkinan dimodifikasi.")

    return {
        "make": make,
        "model": model,
        "lens": lens,
        "software": software,
        "body_serial_present": bool(serial),
        "lens_serial_present": bool(lens_serial),
        "orientation": orientation,
        "capture": {
            "iso": iso,
            "f_number": fnum,
            "exposure_s": exposure,
            "focal_length_mm": focal,
        },
        "device_class": device_class,
        "counter_forensic_signals": signals,
    }


def _perceptual_hashes(img: Image.Image) -> dict[str, str]:
    """aHash, dHash, dan pHash untuk pencocokan gambar duplikat/terpotong."""
    small = img.convert("L").resize((32, 32), Image.Resampling.LANCZOS)
    arr = np.asarray(small, dtype=np.float64)

    def bits_to_hex(bits: np.ndarray) -> str:
        return "".join(str(int(b)) for b in bits.flatten())

    ahash = bits_to_hex(arr.mean() > arr)

    d = arr[:, 1:] > arr[:, :-1]
    dhash = bits_to_hex(d)

    # pHash: DCT 2D pada blok 32x32, ambil 8x8 frekuensi rendah.
    dct = _dct2(arr)[:8, :8]
    phash = bits_to_hex(dct > np.median(dct[1:, 1:]))
    return {"ahash": ahash, "dhash": dhash, "phash": phash}


def _dct2(a: np.ndarray) -> np.ndarray:
    """DCT-II 2D cepat lewat matriks kosinus (ukuran kecil, cukup untuk pHash)."""
    n = a.shape[0]
    k = np.arange(n)
    basis = np.cos(np.pi * (2 * k[None, :] + 1) * k[:, None] / (2 * n))
    basis[:, 0] *= 1 / np.sqrt(2)
    return basis @ a @ basis.T


def _ela(img: Image.Image) -> dict[str, Any]:
    """Error Level Analysis: area hasil suntingan cenderung ber-residu tinggi."""
    rgb = img.convert("RGB")
    buf = io.BytesIO()
    rgb.save(buf, format="JPEG", quality=90)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")
    diff = ImageChops.difference(rgb, resaved)
    arr = np.asarray(diff, dtype=np.float64)
    mean = float(arr.mean())
    p99 = float(np.percentile(arr, 99))
    std = float(arr.std())
    if mean < 1.2 and std < 3.0:
        verdict = "seragam — tidak ada indikasi penyuntingan lokal yang jelas"
    elif mean < 3.0:
        verdict = "residu rendah — penyuntingan ringan/kompresi berulang"
    else:
        verdict = "residu tinggi — indikasi penyuntingan lokal atau tempelan objek"

    vis = Image.fromarray(
        np.clip(arr * (255.0 / max(p99, 1.0)), 0, 255).astype("uint8")
    )
    vis.thumbnail((480, 480))
    return {
        "mean_error": round(mean, 3),
        "std_error": round(std, 3),
        "p99_error": round(p99, 2),
        "verdict": verdict,
        "visualization_png_base64": _png_b64(vis),
    }


def _png_b64(img: Image.Image) -> str:
    import base64

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _jpeg_signature(data: bytes) -> dict[str, Any] | None:
    """Ambil quantization table JPEG sebagai sidik jari kompresi/rantai ekspor."""
    if not data.startswith(b"\xff\xd8"):
        return None
    i = 2
    tables: dict[str, list[int]] = {}
    while i < len(data) - 4:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if i + 4 > len(data):
            break
        length = int.from_bytes(data[i + 2 : i + 4], "big")
        if marker == 0xDB:  # DQT
            j = i + 4
            end = min(i + 2 + length, len(data))
            while j < end:
                pq_tq = data[j]
                precision = pq_tq >> 4
                tid = pq_tq & 0x0F
                j += 1
                n = 128 if precision else 64
                table = data[j : j + n]
                if precision:
                    vals = [
                        int.from_bytes(table[k : k + 2], "big")
                        for k in range(0, len(table), 2)
                    ]
                else:
                    vals = list(table)
                tables[f"table_{tid}"] = vals
                j += n
            break
        if marker in (0xDA, 0xD9):
            break
        i += 2 + length
    if not tables:
        return None
    digest = hashlib.sha256(
        b"".join(bytes(v) for v in tables.values())
    ).hexdigest()[:32]
    return {"tables": tables, "fingerprint": digest}


def _ocr(img: Image.Image) -> dict[str, Any]:
    """OCR opsional: teks pada gambar sering memuat nama tempat/jalan."""
    try:
        import pytesseract  # noqa: PLC0415
    except Exception:
        return {"available": False, "reason": "pytesseract tidak terpasang", "text": ""}
    try:
        text = pytesseract.image_to_string(img.convert("RGB"), lang="eng")
    except Exception as exc:  # engine tesseract belum ada
        return {
            "available": False,
            "reason": f"mesin OCR tidak siap: {type(exc).__name__}",
            "text": "",
        }
    return {"available": True, "text": text.strip()}


def analyze(image_bytes: bytes) -> dict[str, Any]:
    """Jalankan seluruh pipeline forensik pada satu berkas gambar."""
    img = Image.open(io.BytesIO(image_bytes))
    img.load()
    exif = _decode_exif(img)
    gps = _extract_gps(exif)

    taken = (
        exif.get("DateTimeOriginal")
        or exif.get("Exif.DateTimeOriginal")
        or exif.get("DateTime")
    )
    result: dict[str, Any] = {
        "file": {
            "size_bytes": len(image_bytes),
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "megapixels": round(img.width * img.height / 1e6, 2),
            "md5": _sha(image_bytes, "md5"),
            "sha1": _sha(image_bytes, "sha1"),
            "sha256": _sha(image_bytes, "sha256"),
        },
        "hashes_perceptual": _perceptual_hashes(img),
        "exif": exif,
        "exif_present": bool(exif),
        "gps": gps,
        "device": _device_fingerprint(exif),
        "capture_time": {
            "exif_datetime": taken,
            "note": "Waktu EXIF mudah dipalsukan; validasi dengan metadata GPS.",
        },
        "jpeg_signature": _jpeg_signature(image_bytes),
        "ela": _ela(img),
        "ocr": _ocr(img),
        "preview_png_base64": _png_b64(
            _thumb(img, 560)
        ),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
    result["risk_score"] = _risk_score(result)
    return result


def _thumb(img: Image.Image, box: int) -> Image.Image:
    t = img.convert("RGB").copy()
    t.thumbnail((box, box))
    return t


def _risk_score(r: dict[str, Any]) -> dict[str, Any]:
    """Skor 0-100: seberapa banyak jejak identitas/atribusi yang bocor."""
    score = 0
    reasons: list[str] = []
    if r["gps"]:
        score += 40
        reasons.append("Koordinat GPS tertanam (+40)")
    if r["exif"].get("Make") or r["exif"].get("Model"):
        score += 15
        reasons.append("Identitas perangkat foto terbaca (+15)")
    if r["exif"].get("Exif.BodySerialNumber"):
        score += 15
        reasons.append("Nomor seri bodi kamera ada (+15)")
    if r["exif"].get("DateTimeOriginal") or r["exif"].get("Exif.DateTimeOriginal"):
        score += 10
        reasons.append("Waktu pengambilan asli ada (+10)")
    if r["ocr"].get("available") and r["ocr"].get("text"):
        score += 10
        reasons.append("Teks terbaca pada gambar (+10)")
    if r["jpeg_signature"]:
        score += 10
        reasons.append("Sidik jari tabel kompresi tersedia (+10)")
    score = min(score, 100)
    band = (
        "KRITIS" if score >= 70 else "TINGGI" if score >= 45
        else "SEDANG" if score >= 25 else "RENDAH"
    )
    return {
        "score": score,
        "band": band,
        "reasons": reasons,
        "meaning": "Semakin tinggi, semakin mudah gambar ini mengungkap lokasi/pemiliknya.",
    }
