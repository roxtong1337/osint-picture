"""CLI TITIK TERANG — analisis gambar tanpa antarmuka web.

Contoh:
    python3 -m app.cli analyze foto.jpg --purpose penegakan_hukum --attest \
        --analyst "Penyidik A" --descriptors perkotaan,jalan_raya --md laporan.md
    python3 -m app.cli batch ./foto-prajurit --purpose penelitian --attest --csv hasil.csv
    python3 -m app.cli similar foto.jpg
    python3 -m app.cli index foto.jpg --label "hoaks-2026-08"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import batch, forensics, guardrails, report, reverse_search


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--purpose", required=True, help="Tujuan sah (lihat --list-purposes)")
    p.add_argument("--attest", action="store_true", help="Pernyataan tanggung jawab")
    p.add_argument("--analyst", default="", help="Nama analis")
    p.add_argument("--note", default="", help="Catatan tujuan")


def cmd_analyze(args: argparse.Namespace) -> int:
    data = Path(args.image).read_bytes()
    payload = {
        "purpose": args.purpose,
        "attestation": args.attest,
        "analyst_name": args.analyst,
        "note": args.note,
        "descriptors": args.descriptors or "",
        "subject_name": args.subject_name or "",
        "subject_email": args.subject_email or "",
        "subject_phone": args.subject_phone or "",
        "subject_username": args.subject_username or "",
        "subject_org": args.subject_org or "",
        "face_search": args.face_search,
        "online_lookup": args.online,
        "online_engines": [e.strip() for e in (args.engines or "yandex,lens").split(",") if e.strip()],
    }
    result = report.build_report(data, Path(args.image).name, payload)

    if not result["compliance"]["allowed"]:
        print("PERMINTAAN DITOLAK KEPATUHAN:", file=sys.stderr)
        for e in result["compliance"]["errors"]:
            print(f"  - {e}", file=sys.stderr)
        return 2

    s = result["summary"]
    print(f"Kasus        : {result['case_id']}")
    print(f"Audit        : {result['audit_ref']}")
    print(f"Lokasi       : {s['location_headline']}")
    print(f"Kandidat     : {s['candidate_locations']}")
    print(f"Pengenal     : {s['identifiers_found']}")
    print(f"Perangkat    : {s['device']}")
    print(f"Risiko       : {s['risk_score']}/100 ({s['risk_band']})")
    print(f"Autentisitas : {s['authenticity_score']}/100 ({s['authenticity_band']})")
    print(f"Asal unggah  : {s['likely_origin']}")

    online = (result["forensics"].get("online_lookup") or {})
    if online:
        print()
        print("PENCARIAN DARING")
        print(f"  {online.get('summary', '')}")
        geo = online.get("reverse_geocode") or {}
        if geo.get("ok"):
            print(f"  Alamat      : {geo.get('display_name')}")
        y = online.get("yandex") or {}
        if y.get("ok"):
            print(f"  Yandex      : {y.get('site_count')} sumber daring | tag: {', '.join(y.get('tags', [])[:5])}")
            for site in (y.get("sites") or [])[:5]:
                print(f"    - {site['url'][:95]}")
        ln = online.get("lens") or {}
        if ln.get("result_url"):
            print(f"  Lens        : {ln['result_url'][:95]}")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON         : {args.json}")
    if args.md:
        Path(args.md).write_text(result["markdown"], encoding="utf-8")
        print(f"Markdown     : {args.md}")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    result = batch.analyze_folder(
        args.folder,
        {
            "purpose": args.purpose,
            "attestation": args.attest,
            "analyst_name": args.analyst,
            "note": args.note,
        },
    )
    if not result["compliance"]["allowed"]:
        print("PERMINTAAN DITOLAK KEPATUHAN:", file=sys.stderr)
        for e in result["compliance"]["errors"]:
            print(f"  - {e}", file=sys.stderr)
        return 2

    agg = result["aggregate"]
    print(f"Berkas dianalisis : {agg['count']}")
    print(f"Punya GPS         : {agg['gps_present']} ({agg['gps_ratio']*100:.0f}%)")
    print(f"EXIF utuh         : {agg['exif_present']} ({agg['exif_ratio']*100:.0f}%)")
    print(f"Rata-rata risiko  : {agg['avg_risk_score']}/100")
    print(f"Rata autentisitas : {agg['avg_authenticity']}/100")
    print("Rekomendasi:")
    for r in result["recommendations"]:
        print(f"  - {r}")

    if args.csv:
        Path(args.csv).write_text(batch.to_csv(result), encoding="utf-8")
        print(f"CSV               : {args.csv}")
    return 0


def cmd_index(args: argparse.Namespace) -> int:
    entry = reverse_search.index_image(Path(args.image).read_bytes(), args.label)
    print(f"Tersimpan: {entry['entry_id']} — {entry['label']}")
    print(f"Ukuran indeks: {reverse_search.index_size()}")
    return 0


def cmd_similar(args: argparse.Namespace) -> int:
    result = reverse_search.find_similar(
        Path(args.image).read_bytes(), max_distance=args.max_distance
    )
    print(f"Indeks: {result['index_size']} gambar · kemiripan: {result['match_count']}")
    for m in result["matches"]:
        print(f"  - {m['label']}: {m['verdict']} (jarak {m['combined_distance']})")
    print(result["interpretation"])
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from . import verify

    data = Path(args.image).read_bytes()
    v = verify.verify(data)
    print(f"Autentisitas : {v['authenticity_score']}/100 ({v['authenticity_band']})")
    print(f"Asal unggah  : {v['platform_origin']['likely_origin']}")
    print(f"Kompresi     : {v['compression_history']['compression_level']}")
    print(f"Indikasi AI  : {v['ai_generation']['ai_likelihood']} ({v['ai_generation']['band']})")
    print(f"Interpretasi : {v['interpretation']}")
    return 0


def cmd_media(args: argparse.Namespace) -> int:
    from . import media_forensics

    data = Path(args.image).read_bytes()
    payload = {
        "purpose": args.purpose,
        "attestation": args.attest,
        "analyst_name": args.analyst,
        "note": "",
    }
    decision = guardrails.screen_request(payload)
    if not decision["allowed"]:
        print("DITOLAK oleh gerbang kepatuhan:")
        for e in decision["errors"]:
            print(f"  - {e}")
        return 2
    guardrails.log_audit("cli_media", payload, decision)

    r = media_forensics.full_media_report(data)
    faces = r["faces"]
    anom = r["face_anomalies"]
    print(f"Wajah terdeteksi  : {faces.get('count', 0)}")
    print(f"Anomali wajah     : {anom.get('band')} (kecurigaan {anom.get('max_suspicion')})")
    for f in anom.get("findings", []):
        ratio = f["ela_ratio"]
        print(f"  wajah {f['face_index']}: rasio ELA {ratio} — {f['band']}")
        for s in f["signals"]:
            print(f"    - {s}")
    print(f"Indikasi deepfake : {r['deepfake']['score']} ({r['deepfake']['band']})")
    for s in r["deepfake"]["signals"]:
        print(f"    - {s}")
    print(f"Jejak antarmuka   : {len(r['social_media_traces']['traces'])}")
    for t in r["social_media_traces"]["traces"]:
        print(f"    - {t['signal']} → {t['implication']}")
    print(f"\n{r['scope']}")
    return 0


def cmd_purposes(_: argparse.Namespace) -> int:
    print("Tujuan yang diizinkan:")
    for k, v in guardrails.ALLOWED_PURPOSES.items():
        print(f"  {k:26s} {v}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="titik-terang", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analisis satu gambar")
    a.add_argument("image")
    _common(a)
    a.add_argument("--descriptors", help="mis. perkotaan,jalan_raya")
    a.add_argument("--subject-name", dest="subject_name")
    a.add_argument("--subject-email", dest="subject_email")
    a.add_argument("--subject-phone", dest="subject_phone")
    a.add_argument("--subject-username", dest="subject_username")
    a.add_argument("--subject-org", dest="subject_org")
    a.add_argument("--face-search", action="store_true")
    a.add_argument(
        "--online",
        action="store_true",
        help="Pencarian daring: unggah gambar ke Yandex/Lens + geokode balik Nominatim",
    )
    a.add_argument("--engines", default="yandex,lens", help="Mesin daring: yandex,lens")
    a.add_argument("--json", help="Tulis laporan JSON ke berkas")
    a.add_argument("--md", help="Tulis laporan Markdown ke berkas")
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("batch", help="Analisis seluruh folder gambar")
    b.add_argument("folder")
    _common(b)
    b.add_argument("--csv", help="Tulis hasil ke CSV")
    b.set_defaults(func=cmd_batch)

    i = sub.add_parser("index", help="Tambahkan gambar ke indeks hash lokal")
    i.add_argument("image")
    i.add_argument("--label", required=True)
    i.set_defaults(func=cmd_index)

    s = sub.add_parser("similar", help="Cari gambar mirip di indeks lokal")
    s.add_argument("image")
    s.add_argument("--max-distance", type=int, default=6)
    s.set_defaults(func=cmd_similar)

    v = sub.add_parser("verify", help="Verifikasi autentisitas & asal platform")
    v.add_argument("image")
    v.set_defaults(func=cmd_verify)

    m = sub.add_parser("media", help="Deteksi manipulasi media (wajah, tempelan, deepfake)")
    m.add_argument("image")
    m.add_argument("--purpose", required=True)
    m.add_argument("--attest", action="store_true")
    m.add_argument("--analyst", default="")
    m.set_defaults(func=cmd_media)

    p = sub.add_parser("purposes", help="Daftar tujuan yang diizinkan")
    p.set_defaults(func=cmd_purposes)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
