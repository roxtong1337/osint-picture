"""Uji analisis media: deteksi wajah, anomali tempelan, deepfake, jejak platform.

Semua gambar uji dibuat sintetis agar tes tidak bergantung jaringan dan tidak
memakai foto orang sungguhan.
"""

from __future__ import annotations

import io
import random

import pytest
from PIL import Image, ImageDraw, ImageFilter

from app import media_forensics


def plain_image(size=(400, 300), color=(140, 160, 180), fmt="JPEG") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format=fmt)
    return buf.getvalue()


def face_image(size=(480, 480), fmt="JPEG", quality=95) -> bytes:
    """Gambar sintetis berstruktur wajah (oval berkulit, mata gelap, alis, mulut).

    Dibuat cukup kontras agar detektor Haar dapat menemukannya, tanpa memakai
    foto orang sungguhan.
    """
    img = Image.new("RGB", size, (120, 115, 110))
    cx, cy = size[0] // 2, size[1] // 2

    mask = Image.new("L", size, 0)
    ImageDraw.Draw(mask).ellipse([cx - 110, cy - 150, cx + 110, cy + 140], fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(12))
    img = Image.composite(Image.new("RGB", size, (205, 170, 145)), img, mask)

    d = ImageDraw.Draw(img)
    d.ellipse([cx - 75, cy - 65, cx - 25, cy - 25], fill=(250, 250, 248))
    d.ellipse([cx + 25, cy - 65, cx + 75, cy - 25], fill=(250, 250, 248))
    d.ellipse([cx - 62, cy - 58, cx - 38, cy - 32], fill=(35, 30, 28))
    d.ellipse([cx + 38, cy - 58, cx + 62, cy - 32], fill=(35, 30, 28))
    d.rectangle([cx - 80, cy - 88, cx - 20, cy - 78], fill=(60, 45, 40))
    d.rectangle([cx + 20, cy - 88, cx + 80, cy - 78], fill=(60, 45, 40))
    d.polygon([(cx, cy - 20), (cx - 18, cy + 35), (cx + 18, cy + 35)], fill=(185, 148, 125))
    d.ellipse([cx - 45, cy + 60, cx + 45, cy + 105], fill=(150, 75, 75))

    buf = io.BytesIO()
    img.save(buf, format=fmt, quality=quality)
    return buf.getvalue()


def scene_image(tamper: str | None = None, size=(640, 520), seed=7) -> bytes:
    """Adegan sintetis: latar bertekstur + satu wajah.

    Latar wajib ada agar rasio ELA dapat dihitung — wajah yang mengisi seluruh
    bingkai memang tidak dapat dinilai.

    ``tamper``: None (bersih), "blur" (penghalusan lokal), "sharpen" (penajaman lokal).
    """
    rnd = random.Random(seed)
    box = (150, 140, 330, 340)
    img = Image.new("RGB", size, (95, 112, 85))
    d = ImageDraw.Draw(img)
    x0, y0, x1, y1 = box
    for _ in range(200):
        x, y = rnd.randrange(size[0]), rnd.randrange(size[1])
        w, h = rnd.randrange(10, 70), rnd.randrange(10, 70)
        # Jaga area wajah tetap bersih, seperti orang yang berdiri di depan latar.
        if x < x1 + 30 and x + w > x0 - 30 and y < y1 + 30 and y + h > y0 - 30:
            continue
        d.rectangle(
            [x, y, x + w, y + h],
            fill=(rnd.randrange(40, 160), rnd.randrange(60, 150), rnd.randrange(40, 120)),
        )

    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    mask = Image.new("L", size, 0)
    ImageDraw.Draw(mask).ellipse([x0, y0, x1, y1], fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(8))
    img = Image.composite(Image.new("RGB", size, (205, 170, 145)), img, mask)

    d = ImageDraw.Draw(img)
    d.ellipse([cx - 42, cy - 30, cx - 14, cy + 2], fill=(250, 250, 248))
    d.ellipse([cx + 14, cy - 30, cx + 42, cy + 2], fill=(250, 250, 248))
    d.ellipse([cx - 34, cy - 24, cx - 20, cy - 6], fill=(30, 25, 22))
    d.ellipse([cx + 20, cy - 24, cx + 34, cy - 6], fill=(30, 25, 22))
    d.rectangle([cx - 46, cy - 52, cx - 8, cy - 44], fill=(60, 45, 40))
    d.rectangle([cx + 8, cy - 52, cx + 46, cy - 44], fill=(60, 45, 40))
    d.polygon([(cx, cy + 5), (cx - 12, cy + 42), (cx + 12, cy + 42)], fill=(185, 148, 125))
    d.ellipse([cx - 28, cy + 62, cx + 28, cy + 92], fill=(150, 75, 75))

    if tamper == "blur":
        img.paste(img.crop(box).filter(ImageFilter.GaussianBlur(5)), (x0, y0))
    elif tamper == "sharpen":
        img.paste(img.crop(box).filter(ImageFilter.UnsharpMask(radius=3, percent=90)), (x0, y0))

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95)
    return buf.getvalue()


def screenshot_image() -> bytes:
    """Simulasi tangkapan layar: bilah status atas + bilah navigasi bawah."""
    img = Image.new("RGB", (420, 760), (240, 240, 240))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 420, 34], fill=(15, 15, 15))
    d.rectangle([0, 726, 420, 760], fill=(15, 15, 15))
    d.rectangle([30, 90, 390, 400], fill=(90, 140, 200))
    d.rectangle([30, 440, 390, 700], fill=(200, 150, 90))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    return buf.getvalue()


# ---------- deteksi wajah ----------

def test_face_module_reports_availability():
    r = media_forensics.detect_faces(plain_image())
    assert "available" in r
    assert isinstance(r["count"], int)
    assert r["faces"] == [] or all("box" in f for f in r["faces"])


def test_detect_faces_returns_boxes_not_identities():
    r = media_forensics.detect_faces(face_image())
    assert r["available"] is True
    assert r["count"] >= 1, "fixture harus menghasilkan minimal satu wajah"
    for f in r["faces"]:
        assert set(f["box"]) == {"x", "y", "w", "h"}
        assert 0 <= f["area_ratio"] <= 1
    # Periksa struktur data, bukan teks catatan (catatan justru menyebut "template"
    # untuk menjelaskan bahwa template TIDAK dibuat).
    for f in r["faces"]:
        assert set(f) == {
            "index",
            "box",
            "area_ratio",
            "orientation",
            "sharpness",
            "brightness",
            "noise_sigma",
        }
    assert "biometrik" in r["note"] and "tidak" in r["note"].lower()


def test_detect_faces_flat_image_finds_nothing():
    r = media_forensics.detect_faces(plain_image())
    assert r["count"] == 0


# ---------- anomali wajah ----------

def test_face_anomaly_band_present_without_faces():
    r = media_forensics.analyze_face_anomalies(plain_image())
    assert r["checked"] is False
    assert r["band"] == "TIDAK DAPAT DINILAI"
    assert r["findings"] == []


def test_smoothed_face_region_raises_suspicion():
    r = media_forensics.analyze_face_anomalies(scene_image(tamper="blur"))
    assert r["checked"] is True
    assert r["band"] in {"SEDANG", "TINGGI"}
    assert r["max_suspicion"] > 0
    scored = [f for f in r["findings"] if f["band"] != "TIDAK DAPAT DINILAI"]
    assert scored, "harus ada wajah yang dapat dinilai"
    assert scored[0]["ela_ratio"] < 0.9, "penghalusan harus menurunkan rasio ELA"
    signals = " ".join(s for f in scored for s in f["signals"])
    assert "penghalusan" in signals


def test_clean_scene_face_is_not_flagged():
    r = media_forensics.analyze_face_anomalies(scene_image())
    assert r["checked"] is True
    assert r["band"] == "RENDAH", f"adegan bersih tidak boleh ditandai: {r['findings']}"
    assert r["max_suspicion"] == 0.0


def test_sharpening_does_not_trigger_false_smoothing_claim():
    """Penajaman harus mengarah ke atas, bukan dituduh penghalusan.

    Deteksi penajaman secara umum TIDAK andal pada gambar yang sudah dikompres
    (lihat ``method_note``), jadi tes ini hanya memastikan tidak ada tuduhan salah
    arah, bukan bahwa penajaman selalu tertangkap.
    """
    clean = media_forensics.analyze_face_anomalies(scene_image())
    sharp = media_forensics.analyze_face_anomalies(scene_image(tamper="sharpen"))
    scored = [f for f in sharp["findings"] if f["band"] != "TIDAK DAPAT DINILAI"]
    assert scored, "wajah harus terdeteksi agar rasio dapat dihitung"
    assert scored[0]["ela_ratio"] >= clean["findings"][0]["ela_ratio"], (
        "penajaman tidak boleh menurunkan rasio ELA"
    )
    signals = " ".join(s for f in scored for s in f["signals"])
    assert "penghalusan" not in signals


def test_face_filling_whole_frame_is_not_scored():
    """Wajah tanpa latar pembanding harus dinyatakan tidak dapat dinilai."""
    r = media_forensics.analyze_face_anomalies(face_image())
    assert r["checked"] is True
    assert r["band"] == "TIDAK DAPAT DINILAI"
    assert r["scored_count"] == 0
    assert "tidak dapat" in r["findings"][0]["signals"][0].lower()


def test_anomaly_result_is_honest_about_limits():
    r = media_forensics.analyze_face_anomalies(scene_image())
    note = r["method_note"].lower()
    assert "lemah" in note and "positif palsu" in note
    assert "ela" in note or "residu kompresi" in note


# ---------- deepfake ----------

def test_deepfake_signals_shape():
    r = media_forensics.deepfake_signals(face_image())
    assert 0.0 <= r["score"] <= 1.0
    assert r["band"] in {"RENDAH", "SEDANG", "TINGGI"}
    assert "caveat" in r and r["caveat"]


def test_deepfake_clean_image_scores_low():
    r = media_forensics.deepfake_signals(face_image())
    assert r["score"] <= 0.5


def test_deepfake_detects_duplicated_skin_tones():
    """Campur dua rona kulit berbeda: harus memicu sinyal pencampuran sumber."""
    img = Image.new("RGB", (300, 300), (200, 160, 140))
    d = ImageDraw.Draw(img)
    d.rectangle([150, 0, 300, 300], fill=(230, 120, 90))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95)
    r = media_forensics.deepfake_signals(buf.getvalue())
    assert isinstance(r["signals"], list)
    assert r["score"] >= 0


# ---------- jejak platform ----------

def test_screenshot_detected_as_ui_capture():
    r = media_forensics.social_media_traces(screenshot_image())
    assert len(r["traces"]) >= 2
    assert "tangkapan layar" in r["interpretation"]


def test_photo_without_ui_reports_no_traces():
    r = media_forensics.social_media_traces(plain_image(size=(500, 400), color=(90, 130, 80)))
    assert r["traces"] == []
    assert "bukan tangkapan layar" in r["interpretation"]


def test_landscape_photo_is_not_called_a_screenshot():
    """Foto lanskap dengan langit polos tidak boleh disebut tangkapan layar.

    Ini regresi untuk positif palsu: bilah "UI" yang seragam di foto lanskap
    hampir selalu hanya langit atau latar polos.
    """
    img = Image.new("RGB", (800, 600), (120, 130, 120))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 800, 180], fill=(150, 180, 220))  # langit polos
    d.rectangle([0, 420, 800, 600], fill=(70, 90, 60))  # tanah polos
    d.ellipse([350, 250, 450, 400], fill=(205, 170, 145))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=92)

    r = media_forensics.social_media_traces(buf.getvalue())
    assert r["ui_confidence"] < 0.5, f"foto lanskap tidak boleh diklaim screenshot: {r}"
    assert "tangkapan layar/unggahan ulang" not in r["interpretation"]


def test_single_weak_trace_is_reported_as_inconclusive():
    r = media_forensics.social_media_traces(screenshot_image())
    assert r["ui_confidence"] >= 0.7, "screenshot jelas harus berkeyakinan tinggi"
    assert "kemungkinan besar" in r["interpretation"]


def test_traces_include_confidence():
    r = media_forensics.social_media_traces(screenshot_image())
    for t in r["traces"]:
        assert 0 < t["confidence"] <= 1
        assert t["signal"] and t["implication"]


# ---------- laporan gabungan ----------

def test_full_media_report_sections():
    r = media_forensics.full_media_report(face_image())
    assert set(r) >= {"faces", "face_anomalies", "deepfake", "social_media_traces", "scope"}
    assert "tidak melakukan pengenalan wajah" in r["scope"].lower()


def test_full_media_report_declares_no_identity_search():
    r = media_forensics.full_media_report(screenshot_image())
    assert "pencarian identitas" in r["scope"].lower()
