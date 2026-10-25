"""Uji pipeline: forensik EXIF/GPS, geolokasi, pivot identitas, guardrail."""

from __future__ import annotations

import io

import piexif
import pytest
from PIL import Image, ImageDraw

from app import forensics, geolocate, guardrails, identity, report


def _deg_to_rational(value: float) -> tuple:
    deg = int(abs(value))
    minutes = int((abs(value) - deg) * 60)
    seconds = round(((abs(value) - deg) * 60 - minutes) * 60 * 100)
    return ((deg, 1), (minutes, 1), (seconds, 100))


def make_geotagged_jpeg(
    lat: float = -6.1753924,
    lon: float = 106.8271528,
    text: str | None = None,
    with_exif: bool = True,
) -> bytes:
    img = Image.new("RGB", (640, 480), (120, 150, 190))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 300, 640, 480], fill=(60, 60, 60))
    draw.rectangle([420, 120, 600, 300], fill=(200, 190, 170))
    if text:
        draw.text((20, 20), text, fill=(255, 255, 255))
    buf = io.BytesIO()
    if with_exif:
        exif = {
            "0th": {
                piexif.ImageIFD.Make: b"TestCam",
                piexif.ImageIFD.Model: b"TC-1",
                piexif.ImageIFD.Software: b"Adobe Photoshop 25.0",
            },
            "Exif": {
                piexif.ExifIFD.DateTimeOriginal: b"2026:03:14 10:30:00",
                piexif.ExifIFD.BodySerialNumber: b"SN-99887766",
            },
            "GPS": {
                piexif.GPSIFD.GPSLatitudeRef: b"S",
                piexif.GPSIFD.GPSLatitude: _deg_to_rational(lat),
                piexif.GPSIFD.GPSLongitudeRef: b"E",
                piexif.GPSIFD.GPSLongitude: _deg_to_rational(lon),
            },
        }
        img.save(buf, format="JPEG", exif=piexif.dump(exif))
    else:
        img.save(buf, format="JPEG")
    return buf.getvalue()


def test_forensics_extracts_gps_and_device():
    data = make_geotagged_jpeg()
    result = forensics.analyze(data)
    assert result["gps"] is not None
    assert result["gps"]["latitude"] == pytest.approx(-6.1753924, abs=1e-3)
    assert result["gps"]["longitude"] == pytest.approx(106.8271528, abs=1e-3)
    assert result["device"]["make"] == "TestCam"
    assert result["device"]["model"] == "TC-1"
    assert result["device"]["body_serial_present"] is True
    assert result["risk_score"]["score"] >= 70
    assert result["risk_score"]["band"] == "KRITIS"


def test_forensics_hashes_stable_and_perceptual_present():
    data = make_geotagged_jpeg()
    a = forensics.analyze(data)
    b = forensics.analyze(data)
    assert a["file"]["sha256"] == b["file"]["sha256"]
    assert len(a["file"]["md5"]) == 32
    assert set(a["hashes_perceptual"]) == {"ahash", "dhash", "phash"}
    assert a["jpeg_signature"] is not None


def test_stripped_image_yields_no_gps_and_penalizes_score():
    data = make_geotagged_jpeg(with_exif=False)
    result = forensics.analyze(data)
    assert result["gps"] is None
    assert result["exif_present"] is False
    assert result["risk_score"]["score"] < 70


def test_geolocate_prefers_embedded_coordinates():
    analysis = forensics.analyze(make_geotagged_jpeg())
    geo = geolocate.geolocate(analysis, ["perkotaan"])
    assert geo["candidates"][0]["confidence"] == 0.95
    assert "Koordinat tertanam" in geo["candidates"][0]["label"]
    assert any("Street View" in l["provider"] for l in geo["candidates"][0]["links"])
    assert len(geo["reverse_image_links"]) >= 5


def test_geolocate_without_gps_returns_checklist_not_guess():
    analysis = forensics.analyze(make_geotagged_jpeg(with_exif=False))
    geo = geolocate.geolocate(analysis, ["pantai"])
    assert all(c["confidence"] < 0.95 for c in geo["candidates"])
    assert len(geo["verification_checklist"]) >= 5


def test_identity_extracts_and_masks_sensitive_identifiers():
    analysis = {"ocr": {"text": "hubungi budi@example.com atau 081234567890 NIK 3273010101990001"}}
    result = identity.pivot(analysis, {"name": "Budi Santoso"})
    kinds = {i["type"] for i in result["identifiers"]}
    assert "email" in kinds
    assert "phone_id" in kinds
    assert "nik_id" in kinds
    email = next(i for i in result["identifiers"] if i["type"] == "email")
    assert email["value"] == "budi@example.com"
    nik = next(i for i in result["identifiers"] if i["type"] == "nik_id")
    assert nik["masked"] is True
    assert "3273010101990001" not in nik["value"]
    assert result["person_plan"] is not None


def test_identity_no_identifiers_reports_gaps():
    result = identity.pivot({"ocr": {"text": ""}}, {})
    assert result["identifier_count"] == 0
    assert result["evidence_gaps"]


def test_guardrail_blocks_stalking_intent():
    decision = guardrails.screen_request(
        {"purpose": "penegakan_hukum", "attestation": True, "note": "mau lacak mantan saya"}
    )
    assert decision["allowed"] is False
    assert any("stalking" in e or "pengawasan" in e for e in decision["errors"])


def test_guardrail_requires_attestation_and_valid_purpose():
    assert guardrails.screen_request({"purpose": "penegakan_hukum"})["allowed"] is False
    assert guardrails.screen_request({"purpose": "iseng", "attestation": True})["allowed"] is False
    assert (
        guardrails.screen_request({"purpose": "penegakan_hukum", "attestation": True})["allowed"]
        is True
    )


def test_guardrail_warns_on_face_search_for_weak_purpose():
    decision = guardrails.screen_request(
        {"purpose": "penelitian", "attestation": True, "face_search": True}
    )
    assert decision["allowed"] is True
    assert any("wajah" in w for w in decision["warnings"])


def test_report_end_to_end_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DATA_DIR", str(tmp_path))
    import importlib

    importlib.reload(guardrails)
    importlib.reload(report)
    data = make_geotagged_jpeg(text="Jalan Merdeka No 5")
    payload = {
        "purpose": "penegakan_hukum",
        "attestation": True,
        "analyst_name": "Penyidik A",
        "descriptors": "perkotaan",
    }
    result = report.build_report(data, "bukti.jpg", payload)
    assert result["compliance"]["allowed"] is True
    assert result["case_id"]
    assert result["summary"]["candidate_locations"] >= 1
    assert "# Laporan Analisis OSINT Gambar" in result["markdown"]
    assert result["chain_of_custody"]["evidence_sha256"] == result["forensics"]["file"]["sha256"]


def test_report_end_to_end_blocked_still_returns_analysis(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DATA_DIR", str(tmp_path))
    import importlib

    importlib.reload(guardrails)
    importlib.reload(report)
    data = make_geotagged_jpeg()
    payload = {"purpose": "penegakan_hukum", "attestation": False}
    result = report.build_report(data, "x.jpg", payload)
    assert result["compliance"]["allowed"] is False
    assert "case_id" not in result
    assert result["forensics"]["gps"] is not None
