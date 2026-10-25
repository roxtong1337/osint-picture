"""Analisis gambar dengan model AI penglihatan (vision).

Modul ini menjawab keterbatasan alat biasa: kode dapat membaca metadata dan
mencari kemiripan, tetapi tidak dapat memahami isi gambar. Model penglihatan
dapat membaca tulisan pada papan nama, mengenali gaya arsitektur, menandai
landmark, dan menyimpulkan wilayah.

Dua batas yang ditegakkan di sini:

1. **Tidak mengidentifikasi orang.** Prompt melarangnya, dan hasil model
   disaring dengan daftar bidang yang diizinkan. Bidang identitas seperti nama,
   email, atau nomor telepon dibuang walau model mengembalikannya.
2. **Tidak mengarang lokasi.** Model wajib menyertakan alasan dan tingkat
   keyakinan, serta boleh menjawab tidak dapat ditentukan.

Gambar dikirim ke penyedia pihak ketiga, jadi fungsi ini hanya dipanggil bila
analis memintanya.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
from typing import Any

import httpx
from PIL import Image

# Ukuran maksimum sisi terpanjang sebelum dikirim. Menjaga biaya token dan
# mempercepat unggahan tanpa menghilangkan tulisan yang terbaca.
_MAX_SIDE = 1280
_JPEG_QUALITY = 85

# Bidang yang boleh dipakai. Apa pun di luar daftar ini diabaikan, termasuk
# bidang identitas yang mungkin dikembalikan model.
_ALLOWED_FIELDS = (
    "visible_text",
    "signboards",
    "language",
    "scene",
    "landmarks",
    "architecture",
    "vegetation",
    "road_markings",
    "vehicle_plates_format",
    "currency",
    "country_guess",
    "region_guess",
    "candidate_locations",
    "confidence",
    "cannot_determine",
    "limitations",
    "reasoning",
)

# Kata kunci yang menandakan model mencoba mengidentifikasi orang.
_IDENTITY_FLAGS = (
    "nama orang", "nama lengkap", "person's name", "full name", "email address",
    "nomor telepon", "phone number", "nomor hp", "whatsapp", "instagram handle",
    "akun instagram", "akun facebook", "nik", "ktp", "nomor induk",
    "face recognition", "pengenalan wajah", "identitas orang", "identify the person",
    "this person is", "orang ini adalah", "nama dari orang",
)

# Pola yang menandakan data pribadi langsung. Kata kunci saja tidak cukup: model
# dapat menulis alamat surel tanpa menulis frasa "email address", sehingga pola
# harus menangkap bentuk datanya, bukan hanya namanya.
_IDENTITY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"[\w.+-]+@[\w-]+\.[\w.]{2,}", "alamat surel"),
    (r"\b\d{16}\b", "NIK 16 digit"),
    (r"\b(?:\+62|62|0)8\d{7,12}\b", "nomor telepon Indonesia"),
    (r"\bnik\b", "penyebutan NIK"),
    (r"\bemail\b", "penyebutan surel"),
    (r"\b(e-mail|surel)\b", "penyebutan surel"),
    (r"@[A-Za-z0-9_.]{3,}", "nama akun media sosial"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "alamat IP"),
)


def _mentions_identity(text: str) -> list[str]:
    """Kembalikan penanda identitas pribadi yang ditemukan di teks.

    Memeriksa frasa kata kunci dan pola data pribadi (surel, NIK, nomor telepon,
    nama akun). Pola diperlukan karena model dapat menuliskan data pribadi tanpa
    menyebut istilahnya.

    Kata kunci dicocokkan dengan batas kata. Tanpa itu "nik" cocok di dalam
    "ikonik" dan "nama" cocok di dalam "dinamakan", sehingga peringatan identitas
    muncul pada hasil yang sebenarnya bersih.
    """
    text = text or ""
    if not text.strip():
        return []
    low = text.lower()
    found: list[str] = []
    for flag in _IDENTITY_FLAGS:
        if re.search(rf"(?<!\w){re.escape(flag)}(?!\w)", low):
            found.append(flag)
    for pattern, label in _IDENTITY_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            found.append(label)
    return list(dict.fromkeys(found))

_PRIVACY_NOTICE = (
    "PERHATIAN: gambar ini dikirim ke penyedia model AI pihak ketiga untuk analisis visual. "
    "Jangan aktifkan mode ini untuk materi rahasia, bukti yang belum boleh dipublikasikan, "
    "atau data pribadi sensitif."
)

_SYSTEM_PROMPT = """You are a geolocation analyst assistant for lawful forensic work.

Your ONLY task is to help determine WHERE a photo was taken, based on visible evidence.

STRICT RULES:
1. NEVER identify people. Do not guess names, emails, phone numbers, social media
   accounts, national ID numbers, or any personal identity. If a person is visible,
   you may describe only non-identifying attributes relevant to location
   (for example: "uniform style typical of region X").
2. NEVER invent a location. If the evidence is weak, set "cannot_determine": true
   and explain what additional evidence would be needed.
3. Base every claim on something visible. Quote the exact text you read.
4. Give several candidate locations when the evidence is ambiguous, each with its
   own confidence and reasoning. Do not collapse them into one confident answer.

Respond with ONLY a JSON object, no markdown fence, using exactly these keys:
{
  "visible_text": ["every readable string, verbatim, including signs and plates"],
  "signboards": ["street signs, shop names, official boards, verbatim"],
  "language": "language(s) detected in the text",
  "scene": "what the scene shows",
  "landmarks": ["recognisable landmarks or monuments"],
  "architecture": "building style and materials",
  "vegetation": "plants or crops visible",
  "road_markings": "lane markings, road colour, driving side",
  "vehicle_plates_format": "plate format if visible, otherwise empty",
  "currency": "currency symbol or notes if visible",
  "country_guess": "most likely country, or empty",
  "region_guess": "most likely province/state/city, or empty",
  "candidate_locations": [
    {"label": "place name", "confidence": 0.0, "reasoning": "which visible clue supports this"}
  ],
  "confidence": 0.0,
  "cannot_determine": false,
  "limitations": "what is missing or uncertain",
  "reasoning": "brief chain of reasoning from evidence to conclusion"
}
Confidence must be between 0.0 and 1.0. Be honest and calibrated: a wrong confident
answer is worse than an honest low confidence."""


class AIConfigError(RuntimeError):
    """Konfigurasi penyedia AI belum lengkap."""


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


def detect_provider() -> dict[str, str]:
    """Tentukan penyedia AI dari variabel lingkungan yang tersedia.

    Mendukung endpoint bergaya OpenAI (OpenAI, OpenRouter, Groq, Ollama, LM Studio),
    Google Gemini, dan Anthropic. Penyedia dipilih otomatis agar tidak terkunci
    pada satu vendor.
    """
    explicit_key = _env("OSINT_AI_API_KEY")
    explicit_base = _env("OSINT_AI_BASE_URL")

    if explicit_key:
        return {
            "kind": "openai",
            "api_key": explicit_key,
            "base_url": explicit_base or "https://api.openai.com/v1",
            "model": _env("OSINT_AI_MODEL", default="gpt-4o-mini"),
        }

    if openai_key := _env("OPENAI_API_KEY"):
        return {
            "kind": "openai",
            "api_key": openai_key,
            "base_url": _env("OPENAI_BASE_URL", default="https://api.openai.com/v1"),
            "model": _env("OSINT_AI_MODEL", "OPENAI_MODEL", default="gpt-4o-mini"),
        }

    if gemini_key := _env("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        return {
            "kind": "gemini",
            "api_key": gemini_key,
            "base_url": _env(
                "OSINT_AI_BASE_URL", default="https://generativelanguage.googleapis.com/v1beta"
            ),
            "model": _env("OSINT_AI_MODEL", default="gemini-2.0-flash"),
        }

    if anthropic_key := _env("ANTHROPIC_API_KEY"):
        return {
            "kind": "anthropic",
            "api_key": anthropic_key,
            "base_url": _env("OSINT_AI_BASE_URL", default="https://api.anthropic.com/v1"),
            "model": _env("OSINT_AI_MODEL", default="claude-3-5-sonnet-latest"),
        }

    return {"kind": "", "api_key": "", "base_url": "", "model": ""}


def is_configured() -> bool:
    return bool(detect_provider()["api_key"])


def _http_post(url: str, **kw: Any) -> httpx.Response:
    """Pembungkus tipis agar pengujian dapat mengganti transport HTTP."""
    return httpx.post(url, **kw)


def _prepare_image(image_bytes: bytes) -> tuple[str, str]:
    """Perkecil gambar dan ubah ke base64. Mengembalikan (base64, media_type)."""
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img = img.convert("RGB")
        if max(img.size) > _MAX_SIDE:
            ratio = _MAX_SIDE / max(img.size)
            new_size = (max(1, int(img.width * ratio)), max(1, int(img.height * ratio)))
            img = img.resize(new_size, Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=_JPEG_QUALITY)
        return base64.b64encode(buf.getvalue()).decode("ascii"), "image/jpeg"
    except Exception:
        # Format tak dikenal: kirim apa adanya supaya model tetap dapat mencoba.
        return base64.b64encode(image_bytes).decode("ascii"), "image/jpeg"


def _strip_code_fence(text: str) -> str:
    text = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fence:
        return fence.group(1)
    return text


def _parse_json_object(text: str) -> dict[str, Any] | None:
    """Ambil objek JSON dari jawaban model, tahan terhadap teks pembuka."""
    if not text:
        return None
    cleaned = _strip_code_fence(text)
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(cleaned[start : end + 1])
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def sanitize_result(parsed: dict[str, Any]) -> dict[str, Any]:
    """Saring hasil model: hanya bidang yang diizinkan, tanpa isi identitas.

    Bidang di luar daftar diizinkan dibuang. Bila sebuah bidang teks memuat
    penanda identitas, isinya diganti dengan catatan penolakan.
    """
    out: dict[str, Any] = {}
    blocked: list[str] = []

    for field in _ALLOWED_FIELDS:
        if field not in parsed:
            continue
        value = parsed[field]

        if field == "candidate_locations":
            cleaned: list[dict[str, Any]] = []
            for item in value if isinstance(value, list) else []:
                if not isinstance(item, dict):
                    continue
                label = str(item.get("label", "")).strip()
                if not label:
                    continue
                flags = _mentions_identity(label) + _mentions_identity(str(item.get("reasoning", "")))
                if flags:
                    blocked.extend(flags)
                    continue
                try:
                    confidence = float(item.get("confidence", 0.0))
                except (TypeError, ValueError):
                    confidence = 0.0
                cleaned.append(
                    {
                        "label": label,
                        "confidence": max(0.0, min(1.0, confidence)),
                        "reasoning": str(item.get("reasoning", "")).strip(),
                    }
                )
            out[field] = cleaned
            continue

        if isinstance(value, (list, str)):
            text_value = " ".join(_as_string_list(value)) if isinstance(value, list) else value
            flags = _mentions_identity(text_value)
            if flags:
                blocked.extend(flags)
                out[field] = "[dihapus: berisi dugaan identitas pribadi]"
                continue

        out[field] = value

    if blocked:
        out["identity_removed"] = sorted(set(blocked))
        out["identity_notice"] = (
            "Model menyebut unsur identitas pribadi. Bagian itu dibuang dan tidak "
            "ditampilkan. Alat ini tidak mengidentifikasi orang."
        )

    try:
        out["confidence"] = max(0.0, min(1.0, float(out.get("confidence", 0.0))))
    except (TypeError, ValueError):
        out["confidence"] = 0.0

    out["cannot_determine"] = bool(out.get("cannot_determine", False))
    return out


def _call_openai(provider: dict[str, str], b64: str, media_type: str) -> str:
    resp = _http_post(
        f"{provider['base_url'].rstrip('/')}/chat/completions",
        headers={
            "Authorization": f"Bearer {provider['api_key']}",
            "Content-Type": "application/json",
        },
        json={
            "model": provider["model"],
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analyse this image for geolocation. Return JSON only."},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{media_type};base64,{b64}"},
                        },
                    ],
                },
            ],
            "temperature": 0.1,
            "max_tokens": 1500,
        },
        timeout=90.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _call_gemini(provider: dict[str, str], b64: str, media_type: str) -> str:
    url = (
        f"{provider['base_url'].rstrip('/')}/models/{provider['model']}:generateContent"
        f"?key={provider['api_key']}"
    )
    resp = _http_post(
        url,
        headers={"Content-Type": "application/json"},
        json={
            "systemInstruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
            "contents": [
                {
                    "parts": [
                        {"text": "Analyse this image for geolocation. Return JSON only."},
                        {"inline_data": {"mime_type": media_type, "data": b64}},
                    ]
                }
            ],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1500},
        },
        timeout=90.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


def _call_anthropic(provider: dict[str, str], b64: str, media_type: str) -> str:
    resp = _http_post(
        f"{provider['base_url'].rstrip('/')}/messages",
        headers={
            "x-api-key": provider["api_key"],
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": provider["model"],
            "system": _SYSTEM_PROMPT,
            "max_tokens": 1500,
            "temperature": 0.1,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {"type": "base64", "media_type": media_type, "data": b64},
                        },
                        {"type": "text", "text": "Analyse this image for geolocation. Return JSON only."},
                    ],
                }
            ],
        },
        timeout=90.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["content"][0]["text"]


def _call_provider(provider: dict[str, str], b64: str, media_type: str) -> str:
    if provider["kind"] == "gemini":
        return _call_gemini(provider, b64, media_type)
    if provider["kind"] == "anthropic":
        return _call_anthropic(provider, b64, media_type)
    return _call_openai(provider, b64, media_type)


def analyze_image(image_bytes: bytes, geocode: Any = None) -> dict[str, Any]:
    """Minta model penglihatan membaca gambar dan menebak lokasinya.

    `geocode` adalah fungsi opsional (teks -> hasil pencarian tempat). Bila
    diberikan, kandidat lokasi dari model dicoba dicari koordinatnya supaya
    dapat ditampilkan di peta.
    """
    provider = detect_provider()
    if not provider["api_key"]:
        return {
            "enabled": False,
            "ok": False,
            "reason": (
                "Model AI penglihatan belum dikonfigurasi. Isi salah satu variabel: "
                "OSINT_AI_API_KEY (+ OSINT_AI_BASE_URL/OSINT_AI_MODEL), OPENAI_API_KEY, "
                "GEMINI_API_KEY, atau ANTHROPIC_API_KEY."
            ),
            "privacy_notice": _PRIVACY_NOTICE,
            "face_identification_performed": False,
        }

    b64, media_type = _prepare_image(image_bytes)

    try:
        raw = _call_provider(provider, b64, media_type)
    except Exception as exc:  # jaringan atau kuota: jadikan data, bukan ledakan
        return {
            "enabled": True,
            "ok": False,
            "provider": provider["kind"],
            "model": provider["model"],
            "error": f"{type(exc).__name__}: {exc}",
            "privacy_notice": _PRIVACY_NOTICE,
            "face_identification_performed": False,
        }

    parsed = _parse_json_object(raw)
    if parsed is None:
        return {
            "enabled": True,
            "ok": False,
            "provider": provider["kind"],
            "model": provider["model"],
            "error": "Jawaban model bukan JSON yang dapat dibaca.",
            "raw_excerpt": (raw or "")[:400],
            "privacy_notice": _PRIVACY_NOTICE,
            "face_identification_performed": False,
        }

    clean = sanitize_result(parsed)
    candidates = clean.get("candidate_locations") or []

    # Kandidat lokasi dari model dicari koordinatnya agar berguna di peta.
    if geocode and candidates:
        for cand in candidates[:3]:
            try:
                found = geocode(cand["label"], limit=1)
            except Exception:
                continue
            rows = (found or {}).get("results") or []
            if rows:
                cand["latitude"] = rows[0].get("lat")
                cand["longitude"] = rows[0].get("lon")
                cand["geocoded_display_name"] = rows[0].get("display_name")

    return {
        "enabled": True,
        "ok": True,
        "provider": provider["kind"],
        "model": provider["model"],
        **clean,
        "privacy_notice": _PRIVACY_NOTICE,
        "face_identification_performed": False,
        "identity_check": "Model dilarang mengidentifikasi orang; hasil disaring daftar bidang.",
    }


def summary(ai: dict[str, Any]) -> str:
    """Ringkas hasil AI untuk laporan dan antarmuka."""
    if not ai:
        return ""
    if not ai.get("enabled"):
        return ai.get("reason", "Model AI tidak aktif.")
    if not ai.get("ok"):
        return f"Analisis AI gagal: {ai.get('error', 'tidak diketahui')}"

    bits: list[str] = []
    if ai.get("cannot_determine"):
        bits.append("Model menyatakan lokasi tidak dapat ditentukan dari gambar ini")
    if ai.get("country_guess"):
        bits.append(f"negara: {ai['country_guess']}")
    if ai.get("region_guess"):
        bits.append(f"wilayah: {ai['region_guess']}")
    if ai.get("language"):
        bits.append(f"bahasa: {ai['language']}")
    if ai.get("confidence"):
        bits.append(f"keyakinan {ai['confidence']}")
    if ai.get("visible_text"):
        texts = ai["visible_text"][:4]
        bits.append("teks terbaca: " + " | ".join(texts))
    return "; ".join(bits)
