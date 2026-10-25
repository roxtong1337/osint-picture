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
