"""Tes pencarian daring: parser diuji dengan HTML nyata, jaringan tidak dipanggil."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import osint_online

FIXTURE = Path(__file__).parent / "fixtures" / "yandex_cbir_sample.html"


@pytest.fixture()
def yandex_page() -> str:
    return FIXTURE.read_text(encoding="utf-8")


# ------------------------------------------------------------------ parser


def test_parses_real_yandex_sites(yandex_page):
    sites = osint_online._parse_yandex_sites(yandex_page)
    assert len(sites) >= 3, "fixture berisi empat halaman sumber"
    urls = [s["url"] for s in sites]
    assert all(u.startswith("https://") for u in urls)
    # Tidak boleh ada tautan internal Yandex yang ikut terbawa.
    assert not any("yandex." in u for u in urls)
    # Entitas HTML harus sudah dibuka.
    assert not any("&amp;" in u for u in urls)
    # Fixture memuat dimensi gambar pada label tautan.
    assert any(s.get("width") for s in sites)


def test_parses_real_yandex_tags(yandex_page):
    tags = osint_online._parse_yandex_tags(yandex_page)
    assert tags, "fixture memuat label objek"
    assert len(tags) == len(set(tags)), "label harus unik"


def test_parser_returns_empty_on_unrelated_html():
    assert osint_online._parse_yandex_sites("<html><body>kosong</body></html>") == []
    assert osint_online._parse_yandex_tags("<html><body>kosong</body></html>") == []


# --------------------------------------------------------- teks papan nama


def test_place_queries_extract_street_signs():
    text = "JL. ASIA AFRIKA NO 12\nBUKA 24 JAM\nKECAMATAN SUMUR BANDUNG"
    queries = osint_online._place_queries_from_ocr(text)
    assert any("ASIA AFRIKA" in q for q in queries)
    assert any("KECAMATAN" in q for q in queries)
    assert "BUKA 24 JAM" not in queries, "baris tanpa penanda tempat tidak boleh diambil"


def test_place_queries_ignores_short_and_empty_text():
    assert osint_online._place_queries_from_ocr("") == []
    assert osint_online._place_queries_from_ocr("JL\nok") == []


def test_place_queries_deduplicates():
    text = "Jalan Merdeka\nJalan Merdeka"
    assert len(osint_online._place_queries_from_ocr(text)) == 1


# ------------------------------------------------------------ degradasi rapi


def test_online_lookup_survives_network_failure(monkeypatch):
    """Kegagalan jaringan harus jadi data, bukan pengecualian."""

    def boom(*_a, **_k):
        raise OSError("jaringan tidak tersedia")

    monkeypatch.setattr(osint_online, "_http_get", boom)
    monkeypatch.setattr(osint_online, "_http_post", boom)

    out = osint_online.online_lookup(
        b"bukan-gambar", "x.jpg", lat=-6.2, lon=106.8, engines=("yandex", "lens")
    )
    assert out["enabled"] is True
    assert out["reverse_geocode"]["ok"] is False
    assert "error" in out["reverse_geocode"]
    assert out["yandex"]["ok"] is False
    assert out["lens"]["ok"] is False
    assert isinstance(out["summary"], str) and out["summary"]


def test_online_lookup_without_gps_skips_reverse_geocode(monkeypatch):
    monkeypatch.setattr(osint_online, "_http_post", lambda *a, **k: (_ for _ in ()).throw(OSError("mati")))
    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: (_ for _ in ()).throw(OSError("mati")))
    out = osint_online.online_lookup(b"x", "x.jpg", lat=None, lon=None, engines=())
    assert out["reverse_geocode"]["ok"] is False
    assert "dilewati" in out["reverse_geocode"]["reason"]


def test_privacy_notice_always_present(monkeypatch):
    monkeypatch.setattr(osint_online, "_http_post", lambda *a, **k: (_ for _ in ()).throw(OSError("mati")))
    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: (_ for _ in ()).throw(OSError("mati")))
    out = osint_online.online_lookup(b"x", "x.jpg", engines=())
    assert "pihak ketiga" in out["privacy_notice"]
    assert out["face_search_performed"] is False


# ------------------------------------------------------------ geokode balik


def test_nominatim_reverse_builds_address(monkeypatch):
    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "display_name": "Jalan Asia Afrika, Sumur Bandung, Kota Bandung, Jawa Barat, Indonesia",
                "category": "highway",
                "type": "residential",
                "address": {
                    "road": "Jalan Asia Afrika",
                    "suburb": "Sumur Bandung",
                    "city": "Kota Bandung",
                    "state": "Jawa Barat",
                    "postcode": "40111",
                    "country": "Indonesia",
                    "country_code": "id",
                },
            }

    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: FakeResp())
    out = osint_online.nominatim_reverse(-6.9209, 107.6052)
    assert out["ok"] is True
    assert out["city"] == "Kota Bandung"
    assert out["country_code"] == "ID"
    assert "Jalan Asia Afrika" in out["address_parts"]


def test_nominatim_search_empty_query():
    out = osint_online.nominatim_search("   ")
    assert out["ok"] is False
    assert out["results"] == []


def test_nominatim_search_parses_results(monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return [
                {"display_name": "Monumen Nasional, Jakarta", "lat": "-6.1754", "lon": "106.8272",
                 "type": "monument", "category": "historic", "importance": 0.8},
                {"display_name": "tanpa koordinat", "lat": None, "lon": None},
            ]

    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: FakeResp())
    out = osint_online.nominatim_search("Monas")
    assert out["ok"] is True
    assert len(out["results"]) == 1, "baris tanpa koordinat harus dibuang"
    assert out["results"][0]["lat"] == -6.1754


# --------------------------------------------------------- alur Yandex utuh


def test_yandex_reverse_full_flow(monkeypatch, yandex_page):
    class UploadResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"blocks": [{"params": {"cbirId": "1234/abcdef"}}]}

    class PageResp:
        text = yandex_page

        def raise_for_status(self):
            pass

    def fake_post(*_a, **_k):
        return UploadResp()

    def fake_get(*_a, **_k):
        return PageResp()

    monkeypatch.setattr(osint_online, "_http_post", fake_post)
    monkeypatch.setattr(osint_online, "_http_get", fake_get)

    out = osint_online.yandex_reverse(b"palsu")
    assert out["ok"] is True
    assert out["cbir_id"] == "1234/abcdef"
    assert out["site_count"] >= 3
    assert out["tags"]
    assert "cbir_id=" in out["result_url"]
    assert out["interpretation"]


def test_yandex_reverse_reports_no_online_source(monkeypatch):
    class UploadResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"blocks": [{"params": {"cbirId": "1/x"}}]}

    class PageResp:
        text = "<html><body>tidak ada hasil</body></html>"

        def raise_for_status(self):
            pass

    monkeypatch.setattr(osint_online, "_http_post", lambda *a, **k: UploadResp())
    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: PageResp())

    out = osint_online.yandex_reverse(b"palsu")
    assert out["ok"] is True
    assert out["site_count"] == 0
    assert "belum pernah dipublikasikan" in out["interpretation"]


def test_yandex_reverse_handles_upload_failure(monkeypatch):
    monkeypatch.setattr(
        osint_online, "_http_post", lambda *a, **k: (_ for _ in ()).throw(OSError("unggah gagal"))
    )
    out = osint_online.yandex_reverse(b"palsu")
    assert out["ok"] is False
    assert "unggah gagal" in out["error"]


def test_lens_reverse_returns_link(monkeypatch):
    class LensResp:
        status_code = 303
        headers = {"location": "https://www.google.com/search?vsrid=abc"}

    monkeypatch.setattr(osint_online, "_http_post", lambda *a, **k: LensResp())
    out = osint_online.lens_reverse(b"palsu")
    assert out["ok"] is True
    assert out["parseable"] is False
    assert "google.com" in out["result_url"]
    assert "JavaScript" in out["note"]


def test_lens_reverse_without_redirect(monkeypatch):
    class LensResp:
        status_code = 200
        headers: dict[str, str] = {}

    monkeypatch.setattr(osint_online, "_http_post", lambda *a, **k: LensResp())
    out = osint_online.lens_reverse(b"palsu")
    assert out["ok"] is False
    assert "200" in out["error"]


# ------------------------------------------------- integrasi laporan & lokasi


def test_report_skips_network_unless_requested(monkeypatch):
    """Tanpa `online_lookup`, modul daring tidak boleh dipanggil sama sekali."""
    from app import report

    def forbidden(*_a, **_k):
        raise AssertionError("jaringan tidak boleh dipanggil tanpa permintaan eksplisit")

    monkeypatch.setattr(osint_online, "_http_get", forbidden)
    monkeypatch.setattr(osint_online, "_http_post", forbidden)

    import io as _io

    from PIL import Image

    buf = _io.BytesIO()
    Image.new("RGB", (64, 64), (120, 120, 120)).save(buf, "JPEG")
    payload = {"purpose": "penelitian", "attestation": True, "analyst_name": "QA"}
    r = report.build_report(buf.getvalue(), "t.jpg", payload)
    assert r["forensics"].get("online_lookup") is None


def test_geolocate_uses_reverse_geocode_as_top_candidate():
    from app import geolocate

    analysis = {
        "gps": {"latitude": -6.175, "longitude": 106.827},
        "ocr": {"text": ""},
        "online_lookup": {
            "reverse_geocode": {
                "ok": True,
                "lat": -6.175,
                "lon": 106.827,
                "display_name": "Gambir, Jakarta Pusat, Indonesia",
                "address_parts": ["Gambir", "Jakarta Pusat", "Indonesia"],
                "village": "Gambir",
                "city": "Jakarta Pusat",
                "state": "DKI Jakarta",
                "postcode": "10110",
                "country": "Indonesia",
            }
        },
    }
    out = geolocate.geolocate(analysis, [])
    top = out["candidates"][0]
    assert top["rank"] == 1
    assert top["confidence"] == 0.97
    assert "Gambir" in top["label"]
    assert top["detail"]["city"] == "Jakarta Pusat"
    # Peringkat harus tetap berurutan setelah penyisipan.
    assert [c["rank"] for c in out["candidates"]] == list(range(1, len(out["candidates"]) + 1))


def test_geolocate_reports_online_source_pages():
    from app import geolocate

    analysis = {
        "gps": None,
        "ocr": {"text": ""},
        "online_lookup": {
            "reverse_geocode": {"ok": False, "reason": "tidak ada GPS"},
            "yandex": {
                "ok": True,
                "site_count": 2,
                "sites": [{"url": "https://a.example/x.jpg"}, {"url": "https://b.example/y.jpg"}],
                "tags": ["blue"],
                "result_url": "https://yandex.com/images/search?cbir_id=1",
            },
        },
    }
    out = geolocate.geolocate(analysis, [])
    labels = " ".join(c["label"] for c in out["candidates"])
    assert "2 halaman daring" in labels
    assert any("sumber daring" in v for v in out["verification_checklist"])


def test_geolocate_survives_missing_online_block():
    from app import geolocate

    analysis = {"gps": None, "ocr": {"text": ""}}
    out = geolocate.geolocate(analysis, [])
    assert isinstance(out["candidates"], list)


# ------------------------------------------ regresi: normalisasi & bahasa


def test_normalize_strips_indonesian_abbreviations():
    """'JL. ASIA AFRIKA NO. 12' gagal di Nominatim; bentuk normalnya berhasil."""
    assert osint_online.normalize_place_query("JL. ASIA AFRIKA NO. 12") == "Jalan Asia Afrika"
    assert osint_online.normalize_place_query("KEC. SUMUR BANDUNG") == "Kecamatan Sumur Bandung"
    assert osint_online.normalize_place_query("GG. MELATI RT 03 RW 05") == "Gang Melati"
    assert osint_online.normalize_place_query("KEL. BRAGA NO 5") == "Kelurahan Braga"


def test_normalize_handles_empty_and_junk():
    assert osint_online.normalize_place_query("") == ""
    assert osint_online.normalize_place_query("   ") == ""
    assert osint_online.normalize_place_query("NO. 12") == ""


def test_query_variants_loosen_region_words():
    v = osint_online.place_query_variants("KEC. SUMUR BANDUNG")
    assert v[0] == "Kecamatan Sumur Bandung"
    assert "Sumur Bandung" in v


def test_street_and_region_lines_are_combined():
    """Nama jalan tanpa kota cocok ke kota yang salah; penggabungan mencegahnya."""
    ocr = "JL. ASIA AFRIKA NO. 12\nKEC. SUMUR BANDUNG\nBUKA 24 JAM"
    q = osint_online._place_queries_from_ocr(ocr)
    assert "JL. ASIA AFRIKA NO. 12 KEC. SUMUR BANDUNG" in q
    assert "BUKA 24 JAM" not in q


def test_street_alone_is_used_when_no_region():
    q = osint_online._place_queries_from_ocr("JL. SUDIRMAN NO 1\nBUKA 24 JAM")
    assert any("SUDIRMAN" in x for x in q)


def test_search_marks_ambiguous_when_no_region_context():
    """Nama jalan tanpa konteks wilayah harus ditandai lemah, bukan diklaim pasti."""
    import app.osint_online as mod

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"display_name": "Jalan Sudirman, Kota A, Indonesia", "lat": "-1", "lon": "1",
                     "type": "road", "category": "highway", "importance": 0.5}]

    orig = mod._http_get
    mod._http_get = lambda *a, **k: FakeResp()
    try:
        r = mod.search_place_with_variants("JL. SUDIRMAN NO 1")
        assert r["ok"] is True
        assert r["ambiguous"] is True
        assert r["reason"]
    finally:
        mod._http_get = orig


def test_search_not_ambiguous_with_region_context(monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"display_name": "Sumur Bandung, Kota Bandung, Indonesia", "lat": "-6.9",
                     "lon": "107.6", "type": "district", "category": "boundary", "importance": 0.6}]

    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: FakeResp())
    r = osint_online.search_place_with_variants("KEC. SUMUR BANDUNG")
    assert r["ok"] is True
    assert r["ambiguous"] is False
    assert r["best"]["token_overlap"] >= 0.9


def test_search_reports_when_nothing_matches(monkeypatch):
    class EmptyResp:
        def raise_for_status(self):
            pass

        def json(self):
            return []

    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: EmptyResp())
    r = osint_online.search_place_with_variants("JL. NAMA JALAN KARANGAN")
    assert r["ok"] is False
    assert "tidak ada tempat" in r["reason"]


# ------------------------------------------ regresi: deteksi bahasa


def test_indonesian_sign_is_not_labelled_malaysian():
    """Regresi: 'BUKA 24 JAM' dulu membuat papan nama Indonesia dilabeli Malaysia."""
    from app import geolocate

    ocr = "JL. ASIA AFRIKA\nKEC. SUMUR BANDUNG\nBUKA 24 JAM\nDILARANG PARKIR"
    r = geolocate.detect_languages(ocr)
    assert r["languages"][0] == "indonesia"
    assert "malaysia" not in r["languages"], "kata 'buka' tidak boleh menandai Malaysia"
    assert any(w in r["evidence"]["indonesia"] for w in ("kecamatan", "kec", "dilarang"))


def test_malaysian_sign_detected():
    from app import geolocate

    r = geolocate.detect_languages("LEBUH RAYA\nPERSIARAN KLCC\nAWAS")
    assert "malaysia" in r["languages"]


def test_english_sign_detected():
    from app import geolocate

    r = geolocate.detect_languages("MAIN STREET\nNO PARKING\nWARNING")
    assert "english" in r["languages"]


def test_single_weak_word_is_not_enough():
    """Satu kata bersama seperti 'jalan' atau 'buka' tidak boleh menentukan."""
    from app import geolocate

    assert geolocate.detect_languages("JALAN")["languages"] == []
    assert geolocate.detect_languages("BUKA")["languages"] == []
    assert geolocate.detect_languages("")["languages"] == []


def test_language_evidence_lists_trigger_words():
    from app import geolocate

    r = geolocate.detect_languages("DILARANG PARKIR DI JALAN INI")
    assert "indonesia" in r["languages"]
    assert "dilarang" in r["evidence"]["indonesia"]


def test_geolocate_candidate_includes_language_evidence():
    from app import geolocate

    analysis = {"gps": None, "ocr": {"text": "KECAMATAN SUMUR BANDUNG\nDILARANG PARKIR"}}
    out = geolocate.geolocate(analysis, [])
    lang_cands = [c for c in out["candidates"] if "berbahasa" in c["label"]]
    assert lang_cands, "kandidat bahasa harus muncul"
    assert any("kecamatan" in b for b in lang_cands[0]["basis"])


def test_abbreviation_markers_need_word_boundaries():
    """Regresi: 'kec' dulu cocok di dalam 'KECELAKAAN' dan salah menandai Indonesia."""
    from app import geolocate

    assert geolocate.detect_languages("KECELAKAAN DI JALAN INI")["languages"] == []
    assert geolocate.detect_languages("HARGA KECIL")["languages"] == []
    assert geolocate.detect_languages("STOPKONTAK TOKO")["languages"] == []
    # Singkatan yang benar-benar berdiri sendiri tetap dikenali.
    assert geolocate.detect_languages("KEC. SUMUR BANDUNG")["languages"] == ["indonesia"]


def test_region_context_uses_word_boundaries():
    """'Jalan Kota Baru' bukan konteks wilayah; 'Kec. Sumur Bandung' ya."""
    assert osint_online._has_region_context("JL. KOTA BARU NO 1") is False
    assert osint_online._has_region_context("KEC. SUMUR BANDUNG") is True
    assert osint_online._has_region_context("KELURAHAN BRAGA") is True
    assert osint_online._has_region_context("JL. SUDIRMAN NO 1") is False


def test_generic_street_stays_ambiguous_even_with_region():
    """Jalan yang sangat umum tetap lemah walau ada nama kota."""
    import app.osint_online as mod

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"display_name": "Jalan Sudirman, Kota Bandung, Indonesia", "lat": "-6.9",
                     "lon": "107.6", "type": "road", "category": "highway", "importance": 0.5}]

    orig = mod._http_get
    mod._http_get = lambda *a, **k: FakeResp()
    try:
        r = mod.search_place_with_variants("JL. SUDIRMAN NO 1 KEC. SUMUR BANDUNG")
        assert r["ok"] is True
        assert r["ambiguous"] is True, "nama jalan umum tidak boleh diklaim pasti"
    finally:
        mod._http_get = orig


def test_result_exposes_region_context_flag(monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"display_name": "Sumur Bandung, Kota Bandung, Indonesia", "lat": "-6.9",
                     "lon": "107.6", "type": "district", "category": "boundary", "importance": 0.6}]

    monkeypatch.setattr(osint_online, "_http_get", lambda *a, **k: FakeResp())
    r = osint_online.search_place_with_variants("KEC. SUMUR BANDUNG")
    assert r["has_region_context"] is True
    assert r["ambiguous"] is False


def test_duplicate_places_are_shown_once():
    """Dua baris papan nama yang menunjuk tempat sama tidak boleh jadi dua kandidat."""
    from app import geolocate

    same = {
        "ok": True, "ambiguous": False, "has_region_context": True,
        "best": {"display_name": "Jalan Asia Afrika, Bandung, Indonesia", "lat": "-6.9", "lon": "107.6",
                 "matched_variant": "Jalan Asia Afrika", "token_overlap": 1.0},
    }
    analysis = {
        "gps": None, "ocr": {"text": ""},
        "online_lookup": {"sign_place_search": [same, dict(same)]},
    }
    out = geolocate.geolocate(analysis, [])
    places = [c for c in out["candidates"] if "teks gambar" in c["label"]]
    assert len(places) == 1
    assert [c["rank"] for c in out["candidates"]] == list(range(1, len(out["candidates"]) + 1))
