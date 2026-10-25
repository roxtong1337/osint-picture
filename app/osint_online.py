"""Pencarian daring terkendali: pencarian gambar balik dan geokode.

PENTING — modul ini MENGIRIM data ke layanan pihak ketiga:

- `yandex_reverse()` mengunggah gambar ke Yandex Images.
- `lens_reverse()` mengunggah gambar ke Google Lens.
- `nominatim_reverse()` / `nominatim_search()` mengirim koordinat atau kata kunci
  ke OpenStreetMap Nominatim.

Karena itu modul ini hanya dipanggil bila analis secara eksplisit mengaktifkan
mode daring. Setiap panggilan dicatat ke jejak audit. Pencarian wajah daring
TIDAK dijalankan — hanya pencarian objek dan sumber.
"""

from __future__ import annotations

import html
import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

USER_AGENT = "TITIK-TERANG/1.0 (OSINT forensik; kontak: analis)"
TIMEOUT = 45.0

# Nominatim mewajibkan jeda antar permintaan. Kita jaga agar tidak diblokir.
_NOMINATIM_MIN_GAP = 1.1
_last_nominatim_call = 0.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_get(url: str, **kw: Any) -> httpx.Response:
    """Pembungkus tipis agar pengujian dapat mengganti transport HTTP."""
    return httpx.get(url, **kw)


def _http_post(url: str, **kw: Any) -> httpx.Response:
    """Pembungkus tipis agar pengujian dapat mengganti transport HTTP."""
    return httpx.post(url, **kw)


def _throttle_nominatim() -> None:
    global _last_nominatim_call
    gap = time.monotonic() - _last_nominatim_call
    if gap < _NOMINATIM_MIN_GAP:
        time.sleep(_NOMINATIM_MIN_GAP - gap)
    _last_nominatim_call = time.monotonic()


def _clean(text: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text))).strip()


# ---------------------------------------------------------------- geokode


def nominatim_reverse(lat: float, lon: float, zoom: int = 18) -> dict[str, Any]:
    """Ubah koordinat menjadi alamat lengkap. Ini jawaban pasti untuk 'ini di mana'."""
    _throttle_nominatim()
    try:
        r = _http_get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": zoom,
                    "addressdetails": 1, "accept-language": "id,en"},
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "lat": lat, "lon": lon}

    a = data.get("address", {})
    parts = [
        a.get("road"), a.get("neighbourhood") or a.get("hamlet"),
        a.get("village") or a.get("suburb"), a.get("city_district") or a.get("district"),
        a.get("city") or a.get("town") or a.get("municipality"),
        a.get("county"), a.get("state"), a.get("postcode"), a.get("country"),
    ]
    return {
        "ok": True,
        "lat": lat,
        "lon": lon,
        "display_name": data.get("display_name"),
        "address_parts": [p for p in parts if p],
        "road": a.get("road"),
        "village": a.get("village") or a.get("suburb") or a.get("hamlet"),
        "district": a.get("city_district") or a.get("district") or a.get("county"),
        "city": a.get("city") or a.get("town") or a.get("municipality"),
        "state": a.get("state"),
        "postcode": a.get("postcode"),
        "country": a.get("country"),
        "country_code": (a.get("country_code") or "").upper() or None,
        "category": data.get("category"),
        "type": data.get("type"),
        "source": "OpenStreetMap Nominatim",
        "retrieved_at": _now(),
    }


def nominatim_search(query: str, limit: int = 5) -> dict[str, Any]:
    """Cari nama tempat (dari OCR papan nama) menjadi kandidat koordinat."""
    query = (query or "").strip()
    if not query:
        return {"ok": False, "error": "kata kunci kosong", "query": query, "results": []}
    _throttle_nominatim()
    try:
        r = _http_get(
            "https://nominatim.openstreetmap.org/search",
            params={"format": "jsonv2", "q": query, "limit": limit,
                    "addressdetails": 1, "accept-language": "id,en"},
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        rows = r.json()
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "query": query, "results": []}

    return {
        "ok": True,
        "query": query,
        "results": [
            {
                "display_name": row.get("display_name"),
                "lat": float(row["lat"]),
                "lon": float(row["lon"]),
                "type": row.get("type"),
                "category": row.get("category"),
                "importance": row.get("importance"),
            }
            for row in rows
            if row.get("lat") and row.get("lon")
        ],
        "source": "OpenStreetMap Nominatim",
        "retrieved_at": _now(),
    }


# ---------------------------------------------------- pencarian gambar balik


def _parse_yandex_sites(page: str) -> list[dict[str, Any]]:
    m = re.search(r'<section class="CbirSection CbirSitesList".*?</section>', page, re.S)
    if not m:
        return []
    sites: list[dict[str, Any]] = []
    for href, inner in re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', m.group(0), re.S):
        if "yandex." in href:
            continue
        label = _clean(inner)
        entry: dict[str, Any] = {"url": html.unescape(href)}
        # Label biasanya berisi dimensi gambar, mis. "512×512".
        dim = re.match(r"^(\d+)\s*[×x]\s*(\d+)", label)
        if dim:
            entry["width"], entry["height"] = int(dim.group(1)), int(dim.group(2))
        sites.append(entry)
    return sites


def _parse_yandex_tags(page: str) -> list[str]:
    m = re.search(r'<section class="CbirSection CbirTags".*?</section>', page, re.S)
    if not m:
        return []
    tags = [_clean(t) for t in re.findall(r'<span class="Button-Text">(.*?)</span>', m.group(0), re.S)]
    return [t for t in dict.fromkeys(tags) if t]


def _parse_yandex_similar_count(page: str) -> int:
    m = re.search(r'<section class="CbirSection CbirSimilarList".*?</section>', page, re.S)
    if not m:
        return 0
    return len(re.findall(r'CbirSimilarList-Item|serp-item', m.group(0)))


def yandex_reverse(image_bytes: bytes, filename: str = "image.jpg") -> dict[str, Any]:
    """Pencarian gambar balik Yandex: temukan sumber + label objek.

    Mengembalikan halaman yang memuat gambar ini (sumber/unggahan ulang) dan tag
    objek hasil pengenalan otomatis Yandex.
    """
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    request_param = json.dumps({"blocks": [{"block": "b-page_type_search-by-image__link"}]})
    try:
        up = _http_post(
            "https://yandex.com/images/search",
            params={"rpt": "imageview", "format": "json", "request": request_param},
            files={"upfile": (filename, image_bytes, "image/jpeg")},
            headers=headers,
            timeout=TIMEOUT,
            follow_redirects=True,
        )
        up.raise_for_status()
        payload = up.json()
        cbir_id = payload["blocks"][0]["params"]["cbirId"]
    except Exception as exc:
        return {"ok": False, "engine": "Yandex", "error": f"{type(exc).__name__}: {exc}"}

    try:
        page_resp = _http_get(
            "https://yandex.com/images/search",
            params={"rpt": "imageview", "cbir_id": cbir_id, "lang": "en"},
            headers=headers,
            timeout=TIMEOUT,
            follow_redirects=True,
        )
        page_resp.raise_for_status()
        page = page_resp.text
    except Exception as exc:
        return {
            "ok": False,
            "engine": "Yandex",
            "error": f"unggah berhasil tetapi hasil gagal diambil: {type(exc).__name__}: {exc}",
            "cbir_id": cbir_id,
        }

    sites = _parse_yandex_sites(page)
    tags = _parse_yandex_tags(page)
    return {
        "ok": True,
        "engine": "Yandex",
        "cbir_id": cbir_id,
        "result_url": f"https://yandex.com/images/search?rpt=imageview&cbir_id={quote(cbir_id, safe='')}",
        "sites": sites,
        "site_count": len(sites),
        "tags": tags,
        "tags_note": (
            "Label objek berasal dari pengenalan otomatis Yandex dan sering muncul dalam "
            "bahasa Rusia atau Inggris. Gunakan sebagai petunjuk, bukan sebagai fakta."
        ),
        "similar_count": _parse_yandex_similar_count(page),
        "interpretation": (
            "Gambar ini ditemukan di sumber daring — lihat daftar `sites` untuk halaman yang memuatnya."
            if sites
            else "Tidak ada halaman daring yang memuat gambar ini. Gambar kemungkinan belum pernah dipublikasikan, atau hanya beredar tertutup."
        ),
        "source": "Yandex Images (pencarian gambar balik)",
        "retrieved_at": _now(),
    }


def lens_reverse(image_bytes: bytes, filename: str = "image.jpg") -> dict[str, Any]:
    """Unggah ke Google Lens dan kembalikan tautan hasil.

    Google merender hasil dengan JavaScript, sehingga isinya tidak dapat dibaca
    mesin. Fungsi ini mengembalikan tautan hasil siap buka untuk analis.
    """
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "id-ID,id;q=0.9,en;q=0.8"}
    try:
        r = _http_post(
            "https://lens.google.com/v3/upload",
            files={"encoded_image": (filename, image_bytes, "image/jpeg")},
            headers=headers,
            timeout=TIMEOUT,
            follow_redirects=False,
        )
        location = r.headers.get("location")
    except Exception as exc:
        return {"ok": False, "engine": "Google Lens", "error": f"{type(exc).__name__}: {exc}"}

    if not location:
        return {
            "ok": False,
            "engine": "Google Lens",
            "error": f"unggahan tidak mengembalikan tautan hasil (HTTP {r.status_code})",
        }
    return {
        "ok": True,
        "engine": "Google Lens",
        "result_url": location,
        "parseable": False,
        "note": (
            "Google merender hasil dengan JavaScript sehingga tidak dapat dibaca otomatis. "
            "Buka tautan ini untuk melihat hasil visual match, teks, dan objek."
        ),
        "source": "Google Lens",
        "retrieved_at": _now(),
    }


# ---------------------------------------------------------------- orkestrasi


def online_lookup(
    image_bytes: bytes,
    filename: str,
    lat: float | None = None,
    lon: float | None = None,
    ocr_text: str = "",
    engines: tuple[str, ...] = ("yandex", "lens"),
) -> dict[str, Any]:
    """Jalankan pencarian daring yang diminta, dengan degradasi rapi.

    Semua kegagalan dikembalikan sebagai data, bukan pengecualian, agar analisis
    luring tetap utuh walaupun jaringan bermasalah.
    """
    out: dict[str, Any] = {
        "enabled": True,
        "engines": list(engines),
        "privacy_notice": (
            "PERHATIAN: gambar ini dikirim ke layanan pihak ketiga (Yandex/Google) untuk "
            "pencarian gambar balik. Jangan aktifkan mode daring untuk materi rahasia, "
            "bukti yang belum boleh dipublikasikan, atau data pribadi sensitif."
        ),
        "face_search_performed": False,
    }

    if lat is not None and lon is not None:
        out["reverse_geocode"] = nominatim_reverse(lat, lon)
    else:
        out["reverse_geocode"] = {
            "ok": False,
            "reason": "Tidak ada koordinat GPS pada metadata, jadi geokode balik dilewati.",
        }

    # Papan nama pada gambar -> kandidat tempat.
    queries = _place_queries_from_ocr(ocr_text)
    out["sign_place_search"] = [search_place_with_variants(q) for q in queries[:3]] if queries else []
    out["sign_queries"] = queries

    if "yandex" in engines:
        out["yandex"] = yandex_reverse(image_bytes, filename)
    if "lens" in engines:
        out["lens"] = lens_reverse(image_bytes, filename)

    out["summary"] = _online_summary(out)
    return out


def _place_queries_from_ocr(ocr_text: str) -> list[str]:
    """Ambil kandidat nama tempat dari teks pada gambar (papan nama, spanduk).

    Bila gambar memuat nama jalan DAN nama kecamatan/kota, keduanya digabung.
    Tanpa penggabungan, "Jalan Asia Afrika" saja akan cocok ke kota yang salah
    padahal papan nama di gambar sudah menyebut wilayahnya.
    """
    if not ocr_text:
        return []

    street_markers = ("jalan", "jl", "jl.", "gang", "gg", "gg.", "street", "road", "avenue")
    region_markers = (
        "kecamatan", "kec", "kec.", "kelurahan", "kel", "kel.", "kabupaten", "kab", "kab.",
        "kota", "provinsi", "prov", "prov.", "desa", "ds", "dusun", "kampung", "district",
    )

    street_lines: list[str] = []
    region_lines: list[str] = []
    plain_lines: list[str] = []

    for line in ocr_text.splitlines():
        line = line.strip()
        if len(line) < 5 or len(line) > 120:
            continue
        low = line.lower()
        if any(m in low for m in street_markers):
            street_lines.append(line)
        elif any(m in low for m in region_markers):
            region_lines.append(line)
        elif any(m in low for m in ("taman", "blok", "rt", "rw")):
            plain_lines.append(line)

    out: list[str] = []

    # Nama jalan + konteks wilayahnya = kueri jauh lebih tepat.
    for street in street_lines:
        for region in region_lines:
            combined = f"{street} {region}"
            if combined not in out:
                out.append(combined)
    # Bila hanya ada nama jalan, tetap pakai (hasilnya akan ditandai ambigu).
    if not region_lines:
        out.extend(street_lines)
    # Baris wilayah saja tetap berguna sebagai kandidat.
    out.extend(region_lines)
    out.extend(plain_lines)

    return list(dict.fromkeys(out))


# Singkatan yang lazim pada papan nama Indonesia. Nominatim tidak mengenalinya,
# sehingga "JL. ASIA AFRIKA" gagal padahal "Jalan Asia Afrika" berhasil.
_ABBREVIATIONS = {
    "jl": "jalan", "jln": "jalan", "jj": "jalan",
    "gg": "gang", "gg.": "gang",
    "kec": "kecamatan", "kec.": "kecamatan",
    "kel": "kelurahan", "kel.": "kelurahan",
    "kab": "kabupaten", "kab.": "kabupaten",
    "kecamatan.": "kecamatan", "kelurahan.": "kelurahan",
    "prov": "provinsi", "prov.": "provinsi",
    "ds": "desa", "dsn": "dusun", "dus": "dusun",
    "perum": "perumahan", "komp": "komplek",
    "st": "street", "rd": "road", "ave": "avenue",
}

# Kata yang menandakan nomor rumah/RT/RW — bukan bagian nama tempat.
_NOISE_PATTERNS = (
    r"\bno\.?\s*\d+[a-z]?\b",
    r"\bnomor\s*\d+[a-z]?\b",
    r"\brt\.?\s*\d+\b",
    r"\brw\.?\s*\d+\b",
    r"\bblok\s*[a-z0-9]+\b",
)


def _marker_present(text: str, marker: str) -> bool:
    """Cek penanda dengan batas kata agar 'kec' tidak cocok di dalam 'kecelakaan'.

    Penanda non-ASCII (mis. aksara Jepang) tidak punya batas kata, jadi
    dicocokkan langsung.
    """
    if not marker:
        return False
    if marker.isascii():
        return re.search(rf"(?<!\w){re.escape(marker)}(?!\w)", text) is not None
    return marker in text


def _matched_markers(text: str, markers: tuple[str, ...]) -> list[str]:
    """Kembalikan penanda yang cocok, tanpa yang terduplikasi oleh penanda lebih panjang.

    Bila 'kecamatan' sudah cocok, 'kec' tidak perlu dilaporkan lagi.
    """
    hits = [m for m in markers if _marker_present(text, m)]
    hits.sort(key=len, reverse=True)
    kept: list[str] = []
    for hit in hits:
        if not any(hit != other and hit in other for other in kept):
            kept.append(hit)
    return kept


def _has_region_context(raw: str) -> bool:
    """Apakah teks menyebut wilayah administratif secara eksplisit?

    Hanya penanda administratif yang dihitung. Kata "kota" dan "desa" sengaja
    TIDAK dihitung karena sering menjadi bagian nama jalan ("Jalan Kota Baru"),
    sehingga akan keliru dianggap sebagai konteks wilayah.
    """
    text = (raw or "").lower()
    admin_words = (
        "kecamatan", "kelurahan", "kabupaten", "provinsi", "kec", "kel", "kab",
        "prov", "district",
    )
    return any(_marker_present(text, w) for w in admin_words)


def _has_street_marker(raw: str) -> bool:
    """Apakah teks menyebut nama jalan/gang?"""
    text = (raw or "").lower()
    return any(_marker_present(text, w) for w in ("jalan", "jl", "gang", "gg", "street", "road", "avenue"))


def normalize_place_query(raw: str) -> str:
    """Ubah teks papan nama menjadi kueri yang dapat dipahami basis tempat publik.

    Contoh: "JL. ASIA AFRIKA NO. 12" -> "Jalan Asia Afrika".
    """
    text = re.sub(r"[^\w\s\.\-/]", " ", raw or "")
    for pattern in _NOISE_PATTERNS:
        text = re.sub(pattern, " ", text, flags=re.IGNORECASE)
    tokens: list[str] = []
    for tok in text.split():
        key = tok.lower().strip(".")
        tokens.append(_ABBREVIATIONS.get(key, tok))
    cleaned = " ".join(tokens)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .-/")
    if not cleaned:
        return ""
    return cleaned.title()


def place_query_variants(raw: str) -> list[str]:
    """Hasilkan beberapa bentuk kueri, dari paling spesifik ke paling longgar.

    Nama jalan tanpa konteks kota sangat ambigu, jadi analis perlu melihat bahwa
    hasilnya lemah. Varian bertingkat membuat peluang menemukan tetap ada tanpa
    menyamarkan ketidakpastian.
    """
    base = normalize_place_query(raw)
    if not base:
        return []
    variants = [base]
    # Buang kata administratif yang justru mempersempit pencarian terlalu dini.
    for word in ("Kecamatan", "Kelurahan", "Kabupaten", "Provinsi", "Desa", "Kota"):
        stripped = re.sub(rf"\b{word}\b", " ", base)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        if stripped and stripped != base and stripped not in variants:
            variants.append(stripped)
    # Nama jalan saja (tiga kata pertama) sebagai upaya terakhir.
    words = base.split()
    if len(words) > 3:
        head = " ".join(words[:3])
        if head not in variants:
            variants.append(head)
    return variants


def _token_overlap(query: str, display_name: str) -> float:
    """Seberapa banyak kata kueri yang muncul di nama hasil.

    Dipakai untuk menilai apakah hasil pencarian benar-benar cocok atau hanya
    kebetulan nama yang sama di kota lain.
    """
    q = {t.lower() for t in re.findall(r"\w+", query) if len(t) > 2}
    if not q:
        return 0.0
    d = {t.lower() for t in re.findall(r"\w+", display_name or "")}
    return len(q & d) / len(q)


def search_place_with_variants(raw: str, limit: int = 3) -> dict[str, Any]:
    """Cari tempat dari teks papan nama, mencoba beberapa bentuk kueri.

    Mengembalikan hasil terbaik beserta tingkat kecocokan, dan menandai dengan
    jelas bila nama tempat terlalu umum untuk dijadikan bukti lokasi.
    """
    variants = place_query_variants(raw)
    if not variants:
        return {"ok": False, "query": raw, "variants": [], "results": [], "reason": "teks kosong"}

    attempts: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None
    best_score = 0.0

    for variant in variants:
        res = nominatim_search(variant, limit=limit)
        attempts.append({"variant": variant, "ok": res.get("ok"), "count": len(res.get("results") or [])})
        for row in res.get("results") or []:
            score = _token_overlap(variant, row.get("display_name", ""))
            if score > best_score:
                best_score = score
                best = {**row, "matched_variant": variant, "token_overlap": round(score, 2)}

    if not best:
        return {
            "ok": False,
            "query": raw,
            "variants": variants,
            "attempts": attempts,
            "results": [],
            "reason": "tidak ada tempat yang cocok di basis data publik",
        }

    # Kecocokan kata yang tinggi HANYA berarti namanya sama, bukan bahwa lokasinya
    # unik. "Jalan Sudirman" cocok sempurna di puluhan kota. Karena itu keraguan
    # ditentukan oleh ada/tidaknya konteks wilayah, bukan oleh skor kecocokan.
    has_region_context = _has_region_context(raw)
    ambiguous = not has_region_context

    # Nama jalan yang sangat umum tetap lemah walau ada konteks wilayah.
    generic_streets = ("sudirman", "thamrin", "merdeka", "diponegoro", "gatot subroto", "ahmad yani", "pemuda", "mawar", "melati")
    if has_region_context and any(g in (raw or "").lower() for g in generic_streets):
        ambiguous = True

    return {
        "ok": True,
        "query": raw,
        "variants": variants,
        "attempts": attempts,
        "best": best,
        "results": [best],
        "ambiguous": ambiguous,
        "token_overlap": round(best_score, 2),
        "has_region_context": has_region_context,
        "reason": (
            "Teks papan nama tidak menyebut kota/kecamatan, jadi nama ini bisa merujuk ke banyak "
            "tempat dan tidak cukup dijadikan bukti lokasi."
            if ambiguous
            else None
        ),
    }


def _online_summary(out: dict[str, Any]) -> str:
    bits: list[str] = []
    geo = out.get("reverse_geocode") or {}
    if geo.get("ok"):
        bits.append(f"Alamat dari GPS: {geo.get('display_name')}")
    y = out.get("yandex") or {}
    if y.get("ok"):
        bits.append(f"Yandex menemukan {y.get('site_count', 0)} sumber daring dan {len(y.get('tags', []))} label objek")
    if out.get("sign_queries"):
        bits.append(f"{len(out['sign_queries'])} baris teks papan nama dijadikan kandidat tempat")
    if not bits:
        return "Pencarian daring tidak menghasilkan petunjuk lokasi yang dapat dipakai."
    return "; ".join(bits) + "."
