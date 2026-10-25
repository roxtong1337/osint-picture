"""Tes analisis AI penglihatan. Jaringan tidak dipanggil; penyedia ditiru."""

from __future__ import annotations

import io
import json

import pytest
from PIL import Image

from app import ai_vision


def _jpeg(size=(320, 240), color=(120, 150, 180)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "JPEG")
    return buf.getvalue()


@pytest.fixture(autouse=True)
def clear_provider_env(monkeypatch):
    """Pastikan tidak ada kunci API nyata yang ikut terbaca saat tes."""
    for name in (
        "OSINT_AI_API_KEY", "OSINT_AI_BASE_URL", "OSINT_AI_MODEL",
        "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL",
        "GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------ deteksi penyedia


def test_no_provider_configured():
    assert ai_vision.is_configured() is False
    assert ai_vision.detect_provider()["kind"] == ""


def test_detects_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    p = ai_vision.detect_provider()
    assert p["kind"] == "openai"
    assert "api.openai.com" in p["base_url"]


def test_detects_gemini(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-test")
    assert ai_vision.detect_provider()["kind"] == "gemini"


def test_detects_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a-test")
    assert ai_vision.detect_provider()["kind"] == "anthropic"


def test_generic_key_overrides_others(monkeypatch):
    """OSINT_AI_* dipakai lebih dulu agar analis dapat menunjuk endpoint sendiri."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("OSINT_AI_API_KEY", "generic")
    monkeypatch.setenv("OSINT_AI_BASE_URL", "http://localhost:11434/v1")
    p = ai_vision.detect_provider()
    assert p["api_key"] == "generic"
    assert "localhost:11434" in p["base_url"]


def test_unconfigured_returns_reason_not_crash():
    out = ai_vision.analyze_image(_jpeg())
    assert out["enabled"] is False
    assert out["ok"] is False
    assert "OSINT_AI_API_KEY" in out["reason"]


# ------------------------------------------------------------ penyaringan


def test_sanitize_keeps_allowed_fields():
    parsed = {
        "visible_text": ["JL. ASIA AFRIKA"],
        "scene": "jalan kota",
        "confidence": 0.7,
        "candidate_locations": [
            {"label": "Bandung", "confidence": 0.6, "reasoning": "papan nama bahasa Indonesia"}
        ],
    }
    out = ai_vision.sanitize_result(parsed)
    assert out["visible_text"] == ["JL. ASIA AFRIKA"]
    assert out["scene"] == "jalan kota"
    assert out["confidence"] == 0.7
    assert out["candidate_locations"][0]["label"] == "Bandung"


def test_sanitize_drops_unknown_fields():
    parsed = {"scene": "jalan", "secret_extra": "jangan disimpan", "confidence": 0.5}
    out = ai_vision.sanitize_result(parsed)
    assert "secret_extra" not in out


def test_sanitize_clamps_confidence():
    assert ai_vision.sanitize_result({"confidence": 5})["confidence"] == 1.0
    assert ai_vision.sanitize_result({"confidence": -3})["confidence"] == 0.0
    assert ai_vision.sanitize_result({"confidence": "bukan angka"})["confidence"] == 0.0


def test_sanitize_normalises_candidate_confidence():
    parsed = {"candidate_locations": [{"label": "X", "confidence": 9, "reasoning": ""}]}
    out = ai_vision.sanitize_result(parsed)
    assert out["candidate_locations"][0]["confidence"] == 1.0


def test_sanitize_drops_candidate_without_label():
    parsed = {"candidate_locations": [{"confidence": 0.5, "reasoning": "x"}]}
    assert ai_vision.sanitize_result(parsed)["candidate_locations"] == []


# ------------------------------------------------- batas identitas (inti)


def test_identity_in_text_field_is_removed():
    """Model dilarang menyebut identitas; bila tetap muncul, harus dibuang."""
    parsed = {
        "scene": "foto seseorang",
        "visible_text": ["orang ini adalah Budi Santoso, email budi@example.com"],
        "confidence": 0.8,
    }
    out = ai_vision.sanitize_result(parsed)
    assert "budi@example.com" not in json.dumps(out, ensure_ascii=False)
    assert out["visible_text"] == "[dihapus: berisi dugaan identitas pribadi]"
    assert out["identity_removed"]
    assert "tidak mengidentifikasi orang" in out["identity_notice"]


def test_identity_candidate_is_dropped_but_others_kept():
    parsed = {
        "candidate_locations": [
            {"label": "Budi Santoso, email budi@example.com", "confidence": 0.9, "reasoning": "wajah"},
            {"label": "Bandung, Jawa Barat", "confidence": 0.5, "reasoning": "papan nama"},
        ],
        "confidence": 0.6,
    }
    out = ai_vision.sanitize_result(parsed)
    labels = [c["label"] for c in out["candidate_locations"]]
    assert labels == ["Bandung, Jawa Barat"]
    assert out["identity_removed"]


def test_identity_in_reasoning_is_dropped():
    parsed = {
        "candidate_locations": [
            {"label": "Jakarta", "confidence": 0.5, "reasoning": "this person is Andi, NIK 12345"}
        ]
    }
    out = ai_vision.sanitize_result(parsed)
    assert out["candidate_locations"] == []
    assert out["identity_removed"]


def test_identity_flags_detected_in_indonesian_and_english():
    for text in ("nama lengkap orang ini", "email address is x@y.z", "nomor telepon 08123", "NIK 123456"):
        assert ai_vision._mentions_identity(text), f"harus terdeteksi: {text}"


def test_normal_geolocation_text_is_not_flagged():
    """Teks lokasi biasa tidak boleh dianggap identitas."""
    for text in ("JL. ASIA AFRIKA NO 12", "KECAMATAN SUMUR BANDUNG", "MAIN STREET", "Kota Bandung"):
        assert ai_vision._mentions_identity(text) == [], f"tidak boleh terdeteksi: {text}"


def test_face_identification_never_reported_as_performed():
    out = ai_vision.analyze_image(_jpeg())
    assert out["face_identification_performed"] is False


# ------------------------------------------------------------ gambar & JSON


def test_prepare_image_shrinks_large_image():
    big = _jpeg(size=(4000, 3000))
    b64, media = ai_vision._prepare_image(big)
    assert media == "image/jpeg"
    raw = Image.open(io.BytesIO(__import__("base64").b64decode(b64)))
    assert max(raw.size) <= ai_vision._MAX_SIDE


def test_prepare_image_survives_bad_bytes():
    b64, media = ai_vision._prepare_image(b"bukan gambar")
    assert b64
    assert media == "image/jpeg"


def test_parse_json_plain():
    assert ai_vision._parse_json_object('{"a": 1}') == {"a": 1}


def test_parse_json_with_code_fence():
    assert ai_vision._parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}


def test_parse_json_with_surrounding_text():
    text = 'Berikut hasilnya:\n{"a": 1}\nSemoga membantu.'
    assert ai_vision._parse_json_object(text) == {"a": 1}


def test_parse_json_rejects_garbage():
    assert ai_vision._parse_json_object("tidak ada json") is None
    assert ai_vision._parse_json_object("") is None


# ------------------------------------------------------------ alur lengkap


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_openai_flow_end_to_end(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    model_reply = json.dumps(
        {
            "visible_text": ["JL. ASIA AFRIKA NO. 12", "KEC. SUMUR BANDUNG"],
            "signboards": ["JL. ASIA AFRIKA"],
            "language": "indonesia",
            "scene": "jalan kota dengan pertokoan",
            "architecture": "bangunan kolonial",
            "country_guess": "Indonesia",
            "region_guess": "Jawa Barat",
            "candidate_locations": [
                {"label": "Bandung, Jawa Barat", "confidence": 0.75, "reasoning": "papan nama bahasa Indonesia dan nama jalan"}
            ],
            "confidence": 0.7,
            "cannot_determine": False,
            "limitations": "sudut pandang terbatas",
            "reasoning": "teks papan nama menunjukkan Indonesia, nama jalan khas Bandung",
        }
    )
    captured: dict = {}

    def fake_post(url, **kw):
        captured["url"] = url
        captured["json"] = kw.get("json")
        return _FakeResp({"choices": [{"message": {"content": model_reply}}]})

    monkeypatch.setattr(ai_vision, "_http_post", fake_post)
    out = ai_vision.analyze_image(_jpeg())

    assert out["ok"] is True
    assert out["provider"] == "openai"
    assert out["country_guess"] == "Indonesia"
    assert out["candidate_locations"][0]["label"] == "Bandung, Jawa Barat"
    assert "chat/completions" in captured["url"]
    # Prompt harus memuat larangan identifikasi.
    system_msg = captured["json"]["messages"][0]["content"]
    assert "NEVER identify people" in system_msg


def test_gemini_flow(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-test")
    reply = json.dumps({"country_guess": "Indonesia", "confidence": 0.5, "candidate_locations": []})

    def fake_post(url, **kw):
        assert "generateContent" in url
        return _FakeResp({"candidates": [{"content": {"parts": [{"text": reply}]}}]})

    monkeypatch.setattr(ai_vision, "_http_post", fake_post)
    out = ai_vision.analyze_image(_jpeg())
    assert out["ok"] is True
    assert out["provider"] == "gemini"


def test_anthropic_flow(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a-test")
    reply = json.dumps({"country_guess": "Indonesia", "confidence": 0.5, "candidate_locations": []})

    def fake_post(url, **kw):
        assert url.endswith("/messages")
        return _FakeResp({"content": [{"text": reply}]})

    monkeypatch.setattr(ai_vision, "_http_post", fake_post)
    out = ai_vision.analyze_image(_jpeg())
    assert out["ok"] is True
    assert out["provider"] == "anthropic"


def test_network_failure_becomes_data(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def boom(*_a, **_k):
        raise OSError("jaringan putus")

    monkeypatch.setattr(ai_vision, "_http_post", boom)
    out = ai_vision.analyze_image(_jpeg())
    assert out["ok"] is False
    assert "jaringan putus" in out["error"]


def test_unparseable_reply_reported(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        ai_vision, "_http_post",
        lambda *a, **k: _FakeResp({"choices": [{"message": {"content": "maaf saya tidak bisa"}}]}),
    )
    out = ai_vision.analyze_image(_jpeg())
    assert out["ok"] is False
    assert "bukan JSON" in out["error"]


def test_candidates_are_geocoded_when_geocoder_given(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    reply = json.dumps(
        {
            "candidate_locations": [{"label": "Bandung", "confidence": 0.6, "reasoning": "x"}],
            "confidence": 0.6,
        }
    )
    monkeypatch.setattr(
        ai_vision, "_http_post",
        lambda *a, **k: _FakeResp({"choices": [{"message": {"content": reply}}]}),
    )

    def fake_geocode(query, limit=1):
        return {"ok": True, "results": [{"display_name": "Bandung, Jawa Barat, Indonesia", "lat": -6.9, "lon": 107.6}]}

    out = ai_vision.analyze_image(_jpeg(), geocode=fake_geocode)
    cand = out["candidate_locations"][0]
    assert cand["latitude"] == -6.9
    assert "Bandung" in cand["geocoded_display_name"]


def test_geocode_failure_does_not_break_result(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    reply = json.dumps({"candidate_locations": [{"label": "Bandung", "confidence": 0.6, "reasoning": "x"}]})
    monkeypatch.setattr(
        ai_vision, "_http_post",
        lambda *a, **k: _FakeResp({"choices": [{"message": {"content": reply}}]}),
    )

    def broken_geocode(*_a, **_k):
        raise OSError("nominatim mati")

    out = ai_vision.analyze_image(_jpeg(), geocode=broken_geocode)
    assert out["ok"] is True
    assert out["candidate_locations"][0]["label"] == "Bandung"


# ------------------------------------------------------------ ringkasan


def test_summary_reports_unconfigured():
    assert "belum dikonfigurasi" in ai_vision.summary({"enabled": False, "reason": "belum dikonfigurasi"})


def test_summary_reports_failure():
    assert "gagal" in ai_vision.summary({"enabled": True, "ok": False, "error": "kuota habis"}).lower()


def test_summary_includes_key_facts():
    s = ai_vision.summary(
        {
            "enabled": True, "ok": True, "country_guess": "Indonesia",
            "region_guess": "Jawa Barat", "language": "indonesia",
            "confidence": 0.7, "visible_text": ["JL. ASIA AFRIKA"],
        }
    )
    assert "Indonesia" in s
    assert "Jawa Barat" in s
    assert "JL. ASIA AFRIKA" in s


def test_summary_notes_cannot_determine():
    s = ai_vision.summary({"enabled": True, "ok": True, "cannot_determine": True, "confidence": 0.1})
    assert "tidak dapat ditentukan" in s


# ------------------------------------------------------------ integrasi pipeline


def test_report_does_not_call_ai_unless_requested(monkeypatch):
    """Tanpa `ai_vision`, penyedia AI tidak boleh dipanggil."""
    from app import report

    def forbidden(*_a, **_k):
        raise AssertionError("penyedia AI tidak boleh dipanggil tanpa permintaan")

    monkeypatch.setattr(ai_vision, "analyze_image", forbidden)
    payload = {"purpose": "penelitian", "attestation": True, "analyst_name": "QA"}
    r = report.build_report(_jpeg(), "t.jpg", payload)
    assert r["forensics"].get("ai_vision") is None


def test_geolocate_uses_ai_candidates():
    from app import geolocate

    analysis = {
        "gps": None,
        "ocr": {"text": ""},
        "ai_vision": {
            "ok": True,
            "candidate_locations": [
                {"label": "Bandung, Jawa Barat", "confidence": 0.7, "reasoning": "papan nama",
                 "latitude": -6.9, "longitude": 107.6}
            ],
            "visible_text": ["JL. ASIA AFRIKA"],
            "cannot_determine": False,
        },
    }
    out = geolocate.geolocate(analysis, [])
    ai_cands = [c for c in out["candidates"] if "Dugaan AI" in c["label"]]
    assert len(ai_cands) == 1
    assert ai_cands[0]["confidence"] == 0.7
    assert "Bandung" in ai_cands[0]["label"]
    assert ai_cands[0]["links"], "koordinat ada, jadi tautan peta harus muncul"
    assert any("Teks yang terbaca model" in v for v in out["verification_checklist"])


def test_geolocate_marks_low_confidence_ai_candidate_ambiguous():
    from app import geolocate

    analysis = {
        "gps": None, "ocr": {"text": ""},
        "ai_vision": {
            "ok": True,
            "candidate_locations": [{"label": "Mungkin Jakarta", "confidence": 0.3, "reasoning": "samar"}],
            "cannot_determine": False,
        },
    }
    out = geolocate.geolocate(analysis, [])
    cand = [c for c in out["candidates"] if "Dugaan AI" in c["label"]][0]
    assert cand["ambiguous"] is True
    assert "wajib diverifikasi" in cand["precision"]


def test_geolocate_notes_cannot_determine():
    from app import geolocate

    analysis = {
        "gps": None, "ocr": {"text": ""},
        "ai_vision": {
            "ok": True, "candidate_locations": [], "cannot_determine": True,
            "limitations": "tidak ada teks atau landmark",
        },
    }
    out = geolocate.geolocate(analysis, [])
    assert any("tidak dapat ditentukan" in v for v in out["verification_checklist"])


def test_geolocate_notes_identity_removal():
    from app import geolocate

    analysis = {
        "gps": None, "ocr": {"text": ""},
        "ai_vision": {
            "ok": True, "candidate_locations": [], "cannot_determine": False,
            "identity_removed": ["email address"],
        },
    }
    out = geolocate.geolocate(analysis, [])
    assert any("identitas" in v for v in out["verification_checklist"])


def test_geolocate_survives_ai_failure():
    from app import geolocate

    analysis = {"gps": None, "ocr": {"text": ""}, "ai_vision": {"ok": False, "error": "kuota habis"}}
    out = geolocate.geolocate(analysis, [])
    assert isinstance(out["candidates"], list)


# ------------------------------------------ regresi: positif palsu identitas


def test_iconic_does_not_trigger_nik():
    """Regresi: 'ikonik' memuat 'nik' sehingga peringatan identitas palsu muncul."""
    assert ai_vision._mentions_identity("tidak ada landmark ikonik") == []
    assert ai_vision._mentions_identity("bangunan ikonik") == []


def test_renamed_does_not_trigger_nama():
    """Regresi: 'dinamakan' memuat 'nama'."""
    assert ai_vision._mentions_identity("vegetasi dinamakan pohon trembesi") == []


def test_identity_keywords_still_caught_with_boundaries():
    assert ai_vision._mentions_identity("nama lengkap Budi")
    assert ai_vision._mentions_identity("NIK 3273012345678901")
    assert ai_vision._mentions_identity("nomor telepon 081234567890")


def test_clean_model_reply_has_no_identity_warning():
    """Jawaban lokasi yang bersih tidak boleh memicu peringatan identitas."""
    parsed = {
        "visible_text": ["JL. ASIA AFRIKA NO. 12", "KEC. SUMUR BANDUNG"],
        "scene": "jalan kota dengan pertokoan",
        "limitations": "sudut pandang terbatas, tidak ada landmark ikonik",
        "candidate_locations": [
            {"label": "Bandung, Jawa Barat", "confidence": 0.75, "reasoning": "papan nama khas Bandung"}
        ],
        "confidence": 0.7,
    }
    out = ai_vision.sanitize_result(parsed)
    assert "identity_removed" not in out
    assert out["candidate_locations"][0]["label"] == "Bandung, Jawa Barat"
    assert out["visible_text"] == ["JL. ASIA AFRIKA NO. 12", "KEC. SUMUR BANDUNG"]
