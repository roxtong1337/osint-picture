"""Media forensik untuk pertahanan siber: deepfake, anomali wajah, dan jejak media sosial.

Kemampuan di modul ini adalah sisi PERTAHANAN, bukan identifikasi orang:

1. **Deteksi anomali wajah** — menemukan wajah yang ditempel (paste), batas potongan
   yang tidak wajar, dan ketidakcocokan kualitas. Ini alat anti-disinformasi: untuk
   membuktikan sebuah foto PALSU, bukan untuk mencari siapa orangnya.
2. **Deteksi deepfake** — sinyal frekuensi, ketidakcocokan tekstur kulit, dan
   inkonsistensi pencahayaan antar wilayah gambar.
3. **Jejak platform media sosial** — menebak platform asal dari artefak kompresi,
   bilah UI, dan pola watermark.

Modul ini TIDAK melakukan pencarian identitas, tidak membandingkan wajah dengan
basis data, dan tidak menyimpan template biometrik. Tidak ada pengenalan orang.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

CASCADE_DIR = Path(__file__).parent / "cascades"

# Fraksi tepi kotak wajah yang dibuang sebelum menghitung ELA. Kotak Haar lebih
# longgar dari wajah sebenarnya, sehingga tepinya mengencerkan sinyal tempelan.
INNER_INSET = 0.35


def _cv2():
    try:
        import cv2

        return cv2
    except Exception:
        return None


def _cascade(name: str):
    cv2 = _cv2()
    if cv2 is None:
        return None
    path = CASCADE_DIR / name
    if not path.exists():
        return None
    clf = cv2.CascadeClassifier(str(path))
    return None if clf.empty() else clf


def detect_faces(image_bytes: bytes) -> dict[str, Any]:
    """Temukan wajah dalam gambar (deteksi objek, BUKAN pengenalan identitas).

    Yang dikembalikan hanya kotak pembatas, ukuran, dan sudut — cukup untuk analisis
    forensik, tidak cukup untuk mengidentifikasi siapa pun.
    """
    cv2 = _cv2()
    if cv2 is None:
        return {
            "available": False,
            "reason": "OpenCV tidak terpasang",
            "count": 0,
            "faces": [],
            "note": "",
        }

    frontal = _cascade("haarcascade_frontalface_default.xml")
    profile = _cascade("haarcascade_profileface.xml")
    if frontal is None:
        return {
            "available": False,
            "reason": "berkas cascade tidak ditemukan di app/cascades/",
            "count": 0,
            "faces": [],
            "note": "",
        }

    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.asarray(img)
    gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)

    detections: list[tuple[int, int, int, int, str]] = []
    for x, y, w, h in frontal.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(28, 28)):
        detections.append((int(x), int(y), int(w), int(h), "depan"))
    if profile is not None:
        for x, y, w, h in profile.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(28, 28)):
            detections.append((int(x), int(y), int(w), int(h), "samping"))

    detections = _dedupe_boxes(detections)
    faces = [
        {
            "index": i + 1,
            "box": {"x": x, "y": y, "w": w, "h": h},
            "area_ratio": round((w * h) / (img.width * img.height), 4),
            "orientation": orientation,
            "sharpness": _sharpness(gray, x, y, w, h),
            "brightness": round(float(gray[y : y + h, x : x + w].mean()), 1),
            "noise_sigma": _noise_sigma(gray, x, y, w, h),
        }
        for i, (x, y, w, h, orientation) in enumerate(detections)
    ]

    return {
        "available": True,
        "count": len(faces),
        "faces": faces,
        "image_size": {"width": img.width, "height": img.height},
        "note": (
            "Deteksi objek wajah, bukan pengenalan identitas. Tidak ada template "
            "biometrik yang dibuat atau disimpan."
        ),
    }


def _dedupe_boxes(boxes: list[tuple[int, int, int, int, str]]) -> list[tuple[int, int, int, int, str]]:
    """Buang deteksi yang saling menumpuk (frontal + profil pada wajah yang sama)."""
    kept: list[tuple[int, int, int, int, str]] = []
    for box in sorted(boxes, key=lambda b: -(b[2] * b[3])):
        x, y, w, h, _ = box
        cx, cy = x + w / 2, y + h / 2
        overlap = False
        for kx, ky, kw, kh, _ in kept:
            kcx, kcy = kx + kw / 2, ky + kh / 2
            if abs(cx - kcx) < (w + kw) * 0.4 and abs(cy - kcy) < (h + kh) * 0.4:
                overlap = True
                break
        if not overlap:
            kept.append(box)
    return kept


def _sharpness(gray: np.ndarray, x: int, y: int, w: int, h: int) -> float:
    """Varians Laplacian: nilai rendah = area buram (indikasi tempelan)."""
    cv2 = _cv2()
    region = gray[y : y + h, x : x + w]
    if region.size == 0:
        return 0.0
    return round(float(cv2.Laplacian(region, cv2.CV_64F).var()), 2)


def _noise_sigma(gray: np.ndarray, x: int, y: int, w: int, h: int) -> float:
    """Perkiraan tingkat derau lokal — wajah tempelan sering punya derau berbeda."""
    cv2 = _cv2()
    region = gray[y : y + h, x : x + w].astype(np.float64)
    if region.size < 16:
        return 0.0
    med = cv2.medianBlur(region.astype(np.uint8), 3).astype(np.float64)
    return round(float(np.abs(region - med).mean()), 2)


def _region_noise(arr: np.ndarray) -> float:
    cv2 = _cv2()
    if cv2 is None:
        return 0.0
    g = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
    med = cv2.medianBlur(g, 3).astype(np.float64)
    return float(np.abs(g.astype(np.float64) - med).mean())


def _ela_map(arr: np.ndarray) -> np.ndarray:
    """Peta Error Level Analysis: selisih terhadap kompresi ulang kualitas tetap.

    Wilayah yang pernah disunting kehilangan residu kompresi aslinya, sehingga
    nilai ELA-nya menyimpang dari latar. Ini metode baku forensik citra.
    """
    img = Image.fromarray(arr)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    recompressed = np.asarray(Image.open(buf).convert("RGB"), dtype=np.int16)
    return np.abs(arr.astype(np.int16) - recompressed).max(axis=2).astype(np.float64)


def analyze_face_anomalies(image_bytes: bytes, faces: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cari indikasi wajah ditempel / diedit secara lokal.

    Metode: bandingkan residu kompresi (ELA) wilayah wajah dengan wilayah latar.
    Rasio ELA ≈ 1 berarti wajah menyatu dengan latar. Rasio jauh di bawah 1 menandakan
    penghalusan (khas render atau retouch), rasio jauh di atas 1 menandakan penajaman
    atau tempelan dengan riwayat kompresi berbeda.
    """
    faces = faces or detect_faces(image_bytes)
    if not faces.get("available") or not faces.get("count"):
        return {
            "checked": False,
            "reason": "Tidak ada wajah terdeteksi" if faces.get("available") else faces.get("reason"),
            "face_count": 0,
            "max_suspicion": 0.0,
            "band": "TIDAK DAPAT DINILAI",
            "findings": [],
            "method_note": (
                "Tanpa wajah terdeteksi, analisis tempelan tidak dapat dijalankan. "
                "Ini bukan berarti gambar bersih."
            ),
        }

    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.asarray(img)
    ela = _ela_map(arr)
    total_px = arr.shape[0] * arr.shape[1]
    findings: list[dict[str, Any]] = []

    for face in faces["faces"]:
        b = face["box"]
        x, y, w, h = b["x"], b["y"], b["w"], b["h"]

        # Ambil wilayah dalam wajah. Kotak detektor Haar lebih longgar dari wajah
        # sebenarnya; menyertakan tepi kotak akan mengencerkan sinyal tempelan.
        inset_x, inset_y = int(w * INNER_INSET / 2), int(h * INNER_INSET / 2)
        fx0, fy0 = x + inset_x, y + inset_y
        fx1, fy1 = x + w - inset_x, y + h - inset_y
        face_ela = float(ela[fy0:fy1, fx0:fx1].mean())

        mask = np.ones(ela.shape, dtype=bool)
        mask[y : y + h, x : x + w] = False
        bg_px = int(mask.sum())
        bg_ela = float(ela[mask].mean()) if bg_px else 0.0

        signals: list[str] = []
        suspicion = 0.0

        # Wajah yang mengisi hampir seluruh bingkai tidak punya latar pembanding.
        # Melaporkan "RENDAH" di sini akan menyesatkan.
        if bg_px < total_px * 0.10 or bg_ela <= 0.05:
            findings.append(
                {
                    "face_index": face["index"],
                    "box": face["box"],
                    "ela_ratio": None,
                    "face_ela": round(face_ela, 3),
                    "background_ela": round(bg_ela, 3),
                    "sharpness": face["sharpness"],
                    "noise_sigma": face["noise_sigma"],
                    "suspicion": 0.0,
                    "band": "TIDAK DAPAT DINILAI",
                    "signals": [
                        "Latar pembanding terlalu sempit atau terlalu rata; rasio ELA "
                        "tidak dapat dihitung."
                    ],
                }
            )
            continue

        ratio = face_ela / bg_ela

        if ratio < 0.70:
            suspicion += 0.45
            signals.append(
                f"Residu kompresi wajah hanya {ratio:.2f}× latar — khas penghalusan (retouch) "
                "atau wajah hasil render yang tidak pernah dikompresi bersama latar."
            )
        elif ratio > 1.45:
            suspicion += 0.35
            signals.append(
                f"Residu kompresi wajah {ratio:.2f}× latar — khas penajaman atau tempelan "
                "dengan riwayat kompresi berbeda."
            )

        if face["sharpness"] < 25:
            suspicion += 0.15
            signals.append(f"Wajah sangat buram (Laplacian {face['sharpness']}) dibanding bagian lain gambar.")

        if face["brightness"] < 25 or face["brightness"] > 235:
            suspicion += 0.15
            signals.append(f"Kecerahan wajah ekstrem ({face['brightness']}) — pencahayaan tidak wajar.")

        suspicion = min(suspicion, 1.0)
        findings.append(
            {
                "face_index": face["index"],
                "box": face["box"],
                "ela_ratio": round(ratio, 3),
                "face_ela": round(face_ela, 3),
                "background_ela": round(bg_ela, 3),
                "sharpness": face["sharpness"],
                "noise_sigma": face["noise_sigma"],
                "suspicion": round(suspicion, 2),
                "band": "TINGGI" if suspicion >= 0.5 else "SEDANG" if suspicion >= 0.25 else "RENDAH",
                "signals": signals,
            }
        )

    scored = [f for f in findings if f["band"] != "TIDAK DAPAT DINILAI"]
    max_suspicion = max((f["suspicion"] for f in scored), default=0.0)
    if not scored:
        band = "TIDAK DAPAT DINILAI"
    else:
        band = "TINGGI" if max_suspicion >= 0.5 else "SEDANG" if max_suspicion >= 0.25 else "RENDAH"

    return {
        "checked": True,
        "face_count": len(findings),
        "scored_count": len(scored),
        "max_suspicion": round(max_suspicion, 2),
        "band": band,
        "findings": findings,
        "method_note": (
            "Penilaian memakai rasio ELA (residu kompresi) wilayah wajah terhadap latar, "
            "metode baku forensik citra. Metode ini andal untuk mendeteksi penghalusan dan "
            "penajaman lokal, tetapi LEMAH terhadap pergeseran kecerahan halus dan kompresi "
            "ulang ganda. Screenshot dan filter media sosial dapat memberi positif palsu."
        ),
    }


def deepfake_signals(image_bytes: bytes) -> dict[str, Any]:
    """Sinyal indikatif konten hasil generasi/digital face swap."""
    cv2 = _cv2()
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.asarray(img)
    signals: list[str] = []
    score = 0.0

    gray = np.asarray(img.convert("L"), dtype=np.float64)

    # 1. Energi frekuensi tinggi: wajah hasil GAN sering meninggalkan pola aneh.
    if cv2 is not None:
        small = cv2.resize(gray, (256, 256))
        f = np.fft.fftshift(np.fft.fft2(small))
        mag = np.log1p(np.abs(f))
        h, w = mag.shape
        cy, cx = h // 2, w // 2
        low = mag[cy - 20 : cy + 20, cx - 20 : cx + 20].mean()
        high = mag.mean() - low
        ratio = float(high / low) if low else 0.0
        if ratio > 1.35:
            score += 0.3
            signals.append(f"Energi frekuensi tinggi tidak wajar (rasio {ratio:.2f}) — khas artefak upsampling GAN.")

    # 2. Blok 8x8 JPEG tidak rata: indikasi wilayah ditempel ulang.
    if cv2 is not None and arr.shape[0] > 16 and arr.shape[1] > 16:
        g = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY).astype(np.float64)
        block_h = g[: g.shape[0] // 8 * 8, : g.shape[1] // 8 * 8]
        blocks = block_h.reshape(block_h.shape[0] // 8, 8, block_h.shape[1] // 8, 8)
        block_means = blocks.mean(axis=(1, 3))
        block_var = float(np.var(block_means))
        if block_var > 900:
            score += 0.2
            signals.append(f"Variasi antar-blok JPEG tinggi ({block_var:.0f}) — indikasi penyuntingan wilayah.")

    # 3. Konsistensi kroma: face swap sering meninggalkan warna kulit tidak konsisten.
    hsv = np.asarray(img.convert("HSV"), dtype=np.float64)
    hue = hsv[..., 0] * (360 / 255)
    sat = hsv[..., 1] / 255
    skin = (hue > 5) & (hue < 45) & (sat > 0.15) & (sat < 0.75)
    if skin.sum() > 200:
        skin_hue_std = float(np.std(hue[skin]))
        if skin_hue_std > 22:
            score += 0.2
            signals.append(
                f"Sebaran warna kulit lebar (std hue {skin_hue_std:.1f}°) — "
                "khas pencampuran dua sumber gambar."
            )
    else:
        signals.append("Area kulit terlalu kecil untuk dinilai.")

    score = min(score, 1.0)
    return {
        "score": round(score, 2),
        "band": "TINGGI" if score >= 0.5 else "SEDANG" if score >= 0.25 else "RENDAH",
        "signals": signals,
        "caveat": (
            "Tidak ada detektor deepfake yang dapat dipercaya penuh, terutama pada gambar "
            "beresolusi rendah atau sudah dikompres media sosial. Ini indikator awal, bukan bukti."
        ),
    }


def social_media_traces(image_bytes: bytes) -> dict[str, Any]:
    """Tebak jejak platform dari bilah UI, watermark, dan pola dimensi.

    Berguna untuk menentukan gambar berasal dari screenshot aplikasi mana.
    """
    cv2 = _cv2()
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.asarray(img)
    h, w = arr.shape[:2]
    traces: list[dict[str, Any]] = []

    gray = np.asarray(img.convert("L"), dtype=np.float64)
    global_std = float(gray.std())

    # Bilah UI hanya bermakna bila gambar punya konten di bagian lain. Tanpa syarat
    # ini, foto polos (std rendah di mana-mana) akan salah disebut screenshot.
    def band_is_ui(band: np.ndarray, label: str, implication: str, confidence: float) -> None:
        if band.size == 0:
            return
        band_std = float(band.std())
        if global_std > 18 and band_std < 20 and band_std < global_std * 0.35:
            traces.append(
                {
                    "signal": f"{label} seragam (std {band_std:.1f}) sementara isi gambar bervariasi (std {global_std:.1f})",
                    "implication": implication,
                    "confidence": confidence,
                }
            )

    # Screenshot aplikasi ponsel hampir selalu portrait. Syarat ini mencegah foto
    # lanskap dengan langit polos disebut tangkapan layar.
    portrait = h > w * 1.15

    if portrait and h > 40:
        band_is_ui(
            gray[: max(1, int(h * 0.04))],
            "bilah status / UI di bagian atas",
            "kemungkinan screenshot aplikasi ponsel",
            0.6,
        )
    if portrait and h > 60:
        band_is_ui(
            gray[int(h * 0.96) :],
            "bilah navigasi di bagian bawah",
            "kemungkinan screenshot dengan tombol navigasi",
            0.55,
        )

    # Watermark sudut: area seragam yang menyimpang dari kecerahan rata-rata gambar.
    # Dilewati bila sudut itu bagian dari bidang polos besar (langit, tanah, dinding);
    # pada kasus itu "penyimpangan" hanyalah pemandangan, bukan watermark.
    corner = max(30, min(60, min(h, w) // 6))
    if h > corner * 2 and w > corner * 2 and global_std > 18:
        bottom_band_std = float(gray[int(h * 0.9) :].std())
        corners = {
            "kiri-bawah": arr[h - corner :, :corner],
            "kanan-bawah": arr[h - corner :, w - corner :],
        }
        if bottom_band_std >= 18:
            for name, c in corners.items():
                if c.size and c.std() < 30 and abs(float(c.mean()) - float(arr.mean())) > 35:
                    traces.append(
                        {
                            "signal": f"pola seragam menyimpang di sudut {name}",
                            "implication": "kemungkinan watermark platform",
                            "confidence": 0.5,
                        }
                    )

    # Garis tepi vertikal khas bilah sisi tangkapan layar ponsel. Hanya bermakna pada
    # orientasi portrait; pada foto lanskap, tepi vertikal kuat biasanya hanya batas
    # objek atau horizon.
    if cv2 is not None and global_std > 18 and portrait:
        g8 = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
        edges = cv2.Canny(g8, 60, 160)
        col_density = edges.mean(axis=0)
        mean_density = float(col_density.mean())
        if mean_density > 0:
            strong_cols = int((col_density > mean_density * 3.0).sum())
            if strong_cols >= 2:
                traces.append(
                    {
                        "signal": f"{strong_cols} garis vertikal kuat",
                        "implication": "kemungkinan ada batas UI / bilah sisi",
                        "confidence": 0.45,
                    }
                )

    # Satu sinyal lemah tidak cukup untuk menyimpulkan "tangkapan layar". Foto biasa
    # dengan latar polos sering menyerupai bilah UI. Skor gabungan memakai keyakinan
    # tertinggi, ditambah bonus bila beberapa sinyal saling mendukung.
    if not traces:
        confidence = 0.0
    else:
        confidence = max(t["confidence"] for t in traces)
        if len(traces) >= 2:
            confidence = min(confidence + 0.15, 0.9)
        if len(traces) >= 3:
            confidence = min(confidence + 0.1, 0.95)

    if confidence >= 0.7:
        interpretation = (
            f"Beberapa jejak antarmuka saling mendukung (keyakinan {confidence:.2f}); "
            "gambar kemungkinan besar tangkapan layar atau unggahan ulang."
        )
    elif confidence >= 0.5:
        interpretation = (
            f"Ditemukan jejak antarmuka (keyakinan {confidence:.2f}), tetapi belum konklusif. "
            "Periksa manual apakah ada bilah status, tombol navigasi, atau watermark."
        )
    elif traces:
        interpretation = (
            f"Jejak antarmuka sangat lemah (keyakinan {confidence:.2f}) dan dapat berasal dari "
            "latar polos biasa. Jangan jadikan dasar kesimpulan."
        )
    else:
        interpretation = (
            "Tidak ada jejak antarmuka yang jelas — kemungkinan foto langsung, bukan tangkapan layar."
        )

    return {
        "dimensions": {"width": w, "height": h},
        "aspect_ratio": round(w / h, 3) if h else 0,
        "ui_confidence": round(confidence, 2),
        "traces": traces,
        "interpretation": interpretation,
    }


def full_media_report(image_bytes: bytes) -> dict[str, Any]:
    """Jalankan seluruh analisis media dalam satu panggilan."""
    faces = detect_faces(image_bytes)
    return {
        "faces": faces,
        "face_anomalies": analyze_face_anomalies(image_bytes, faces),
        "deepfake": deepfake_signals(image_bytes),
        "social_media_traces": social_media_traces(image_bytes),
        "scope": (
            "Analisis forensik media untuk mendeteksi manipulasi. Modul ini tidak "
            "melakukan pengenalan wajah atau pencarian identitas."
        ),
    }
