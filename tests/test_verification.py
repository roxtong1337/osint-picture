"""Uji modul verifikasi autentisitas, pencarian balik, dan mode batch."""

from __future__ import annotations

import io
import random

import pytest
from PIL import Image, ImageDraw

from app import batch, forensics, guardrails, reverse_search, verify


def textured_image(seed: int = 1, size: tuple[int, int] = (480, 360), fmt: str = "JPEG", **kw) -> bytes:
    """Buat gambar bertekstur (bukan rata) agar hash perseptual bermakna."""
    rnd = random.Random(seed)
    img = Image.new("RGB", size, (110, 140, 180))
    draw = ImageDraw.Draw(img)
    for _ in range(220):
        x, y = rnd.randrange(size[0]), rnd.randrange(size[1])
        w, h = rnd.randrange(6, 60), rnd.randrange(6, 60)
        draw.rectangle(
            [x, y, x + w, y + h],
            fill=(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)),
        )
    buf = io.BytesIO()
    img.save(buf, format=fmt, **kw)
    return buf.getvalue()


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    """Setiap tes memakai direktori data sendiri agar indeks tidak bocor."""
    monkeypatch.setenv("OSINT_DATA_DIR", str(tmp_path))
    import importlib

    importlib.reload(guardrails)
    importlib.reload(reverse_search)
    importlib.reload(batch)
    yield
    importlib.reload(guardrails)
    importlib.reload(reverse_search)
    importlib.reload(batch)


# ---------- verify ----------

def test_verify_detects_clean_camera_image():
    data = textured_image(1)
    v = verify.verify(data)
    assert 0 <= v["authenticity_score"] <= 100
    assert v["authenticity_band"] in {"TINGGI", "SEDANG", "RENDAH", "SANGAT RENDAH"}
    assert v["platform_origin"]["likely_origin"]
    assert v["compression_history"]["compression_level"]


def test_verify_flags_instagram_software_marker():
    buf = io.BytesIO()
    img = Image.new("RGB", (1080, 1080), (200, 100, 50))
    exif = img.getexif()
    exif[0x0131] = "Instagram"  # Software
    img.save(buf, format="JPEG", exif=exif)
    v = verify.verify(buf.getvalue())
    assert v["platform_origin"]["likely_origin"] == "instagram"
    assert v["platform_origin"]["confidence"] >= 0.9


def test_verify_flags_generative_software():
    buf = io.BytesIO()
    img = Image.new("RGB", (512, 512), (30, 30, 30))
    exif = img.getexif()
    exif[0x0131] = "Stable Diffusion WebUI"
    img.save(buf, format="JPEG", exif=exif)
    v = verify.verify(buf.getvalue())
    assert v["ai_generation"]["ai_likelihood"] >= 0.6
    assert v["ai_generation"]["band"] == "TINGGI"
    assert "AI" in v["interpretation"] or "laboratorium" in v["interpretation"]


def test_verify_low_metadata_reduces_authenticity():
    clean = verify.verify(textured_image(2, quality=95))
    stripped = verify.verify(textured_image(2, quality=95))
    assert stripped["authenticity_score"] <= 100
    assert clean["authenticity_score"] >= stripped["authenticity_score"]


def test_verify_reports_score_notes_when_metadata_missing():
    v = verify.verify(textured_image(3))
    assert any("EXIF kosong" in n for n in v["score_notes"])


# ---------- reverse_search ----------

def test_hamming_distance_basic():
    assert reverse_search.hamming("0000", "0000") == 0
    assert reverse_search.hamming("0000", "1111") == 4
    assert reverse_search.hamming("00", "0011") == 4


def test_index_dedupes_identical_file():
    data = textured_image(4)
    first = reverse_search.index_image(data, "a")
    second = reverse_search.index_image(data, "b")
    assert first["entry_id"] == second["entry_id"]
    assert second["already_indexed"] is True
    assert reverse_search.index_size() == 1


def test_similar_finds_exact_match():
    data = textured_image(5)
    reverse_search.index_image(data, "asli")
    result = reverse_search.find_similar(data)
    assert result["match_count"] == 1
    assert result["matches"][0]["sha256_match"] is True
    assert "SAMA PERSIS" in result["matches"][0]["verdict"]


def test_similar_ignores_flat_images_as_unreliable():
    flat = Image.new("RGB", (300, 200), (10, 200, 10))
    buf = io.BytesIO()
    flat.save(buf, format="JPEG")
    reverse_search.index_image(buf.getvalue(), "polos")
    other = Image.new("RGB", (300, 200), (200, 10, 10))
    buf2 = io.BytesIO()
    other.save(buf2, format="JPEG")
    result = reverse_search.find_similar(buf2.getvalue())
    assert result["reliable"] is False
    assert result["match_count"] == 0
    assert "tidak dapat diandalkan" in result["interpretation"]


def test_similar_distinguishes_different_images():
    a = textured_image(6)
    b = textured_image(99)
    reverse_search.index_image(a, "gambar-a")
    result = reverse_search.find_similar(b, max_distance=4)
    labels = [m["label"] for m in result["matches"]]
    assert "gambar-a" not in labels or result["matches"][0]["sha256_match"] is False


def test_pivot_plan_includes_gps_step_when_gps_present(tmp_path):
    import piexif

    def rat(v):
        d = int(abs(v)); m = int((abs(v) - d) * 60); s = round((((abs(v) - d) * 60) - m) * 60 * 100)
        return ((d, 1), (m, 1), (s, 100))

    img = Image.new("RGB", (200, 150), (100, 100, 100))
    exif = {
        "0th": {},
        "Exif": {},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"S",
            piexif.GPSIFD.GPSLatitude: rat(-6.2),
            piexif.GPSIFD.GPSLongitudeRef: b"E",
            piexif.GPSIFD.GPSLongitude: rat(106.8),
        },
    }
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=piexif.dump(exif))
    analysis = forensics.analyze(buf.getvalue())
    plan = reverse_search.pivot_plan(analysis)
    actions = " ".join(s["action"] for s in plan["steps"])
    assert "koordinat" in actions.lower()
    assert len(plan["steps"]) >= 5


def test_record_finding_and_attribution_chain():
    reverse_search.record_finding("case-1", "TinEye", "https://x", "muncul 2024", 0.8, "analis")
    reverse_search.record_finding("case-1", "Google", "https://y", "sumber asli", 0.7, "analis")
    chain = reverse_search.attribution_chain("case-1")
    assert chain["finding_count"] == 2
    assert chain["independent_sources"] == 2
    assert chain["verdict"] == "SIAP DILAPORKAN"


def test_attribution_chain_insufficient_with_one_source():
    reverse_search.record_finding("case-2", "TinEye", "https://x", "", 0.9)
    chain = reverse_search.attribution_chain("case-2")
    assert chain["verdict"] == "BELUM CUKUP"


def test_ledger_filters_by_case():
    reverse_search.record_finding("case-a", "TinEye", "https://x")
    reverse_search.record_finding("case-b", "Google", "https://y")
    assert reverse_search.ledger("case-a")["count"] == 1
    assert reverse_search.ledger()["count"] == 2


# ---------- batch ----------

def test_batch_aggregates_metadata_exposure():
    items = [
        ("foto1.jpg", textured_image(11)),
        ("foto2.jpg", textured_image(12)),
        ("foto3.jpg", textured_image(13)),
    ]
    payload = {"purpose": "penelitian", "attestation": True, "analyst_name": "Peneliti"}
    result = batch.analyze_many(items, payload)
    assert result["compliance"]["allowed"] is True
    assert result["count"] == 3
    agg = result["aggregate"]
    assert agg["count"] == 3
    assert 0.0 <= agg["gps_ratio"] <= 1.0
    assert agg["avg_risk_score"] >= 0
    assert result["recommendations"]


def test_batch_blocked_without_attestation():
    result = batch.analyze_many(
        [("f.jpg", textured_image(20))],
        {"purpose": "penelitian", "attestation": False},
    )
    assert result["compliance"]["allowed"] is False


def test_batch_records_per_file_errors():
    result = batch.analyze_many(
        [("rusak.jpg", b"bukan gambar sama sekali")],
        {"purpose": "penelitian", "attestation": True},
    )
    assert result["count"] == 0
    assert result["errors"] and result["errors"][0]["file"] == "rusak.jpg"


def test_batch_csv_has_header_and_rows():
    result = batch.analyze_many(
        [("a.jpg", textured_image(30))],
        {"purpose": "penelitian", "attestation": True},
    )
    csv_text = batch.to_csv(result)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("file,sha256,format")
    assert len(lines) == 2
    assert "a.jpg" in lines[1]


def test_analyze_folder_reads_images(tmp_path):
    folder = tmp_path / "kumpulan"
    folder.mkdir()
    (folder / "x.jpg").write_bytes(textured_image(40))
    (folder / "y.png").write_bytes(textured_image(41, fmt="PNG"))
    (folder / "catatan.txt").write_text("bukan gambar")
    result = batch.analyze_folder(folder, {"purpose": "penelitian", "attestation": True})
    assert result["count"] == 2


# ---------- report integration ----------

def test_report_includes_verification_and_pivot():
    from app import report

    data = textured_image(50)
    result = report.build_report(
        data,
        "uji.jpg",
        {"purpose": "verifikasi_jurnalistik", "attestation": True, "descriptors": "perkotaan"},
    )
    assert "verification" in result
    assert "reverse_search" in result
    assert result["indexed_as"]
    md = result["markdown"]
    assert "## 2. Verifikasi Autentisitas" in md
    assert "## 3. Rencana Pencarian Gambar Balik" in md
    assert "## 5. Analisis Media & Deteksi Manipulasi" in md
    assert "## 6. Pivot Identitas" in md
    assert "## 7. Kepatuhan & Rantai Bukti" in md
