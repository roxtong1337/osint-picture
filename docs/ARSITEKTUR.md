# Arsitektur TITIK TERANG

## Alur data

```
Peserta unggah gambar
        │
        ▼
[Gerbang Kepatuhan]  purpose sah? attestation? niat diblokir?
        │  lolos                    │ ditolak
        ▼                           ▼
[Forensik] EXIF · GPS · hash ·   hasil forensik teknis tetap
perangkat · ELA · OCR · pHash    dikembalikan + alasan penolakan
        │
        ▼
[Geolokasi] koordinat → peta, zona waktu, elevasi matahari,
            statistik warna, kandidat berperingkat, daftar periksa
        │
        ▼
[Pivot Identitas] pengenal + sensor + tautan sumber publik resmi
        │
        ▼
[Laporan] ringkasan · Markdown · JSON · rantai kustodi · ID kasus
        │
        ▼
[Jejak Audit] data/audit.jsonl (append-only)
```

## Keputusan desain

**1. Gerbang kepatuhan sebelum analisis, bukan sesudah.**
Analisis tetap dijalankan walau permintaan ditolak, tetapi hasilnya tidak disimpan sebagai kasus dan hanya dipakai untuk memberi tahu analis apa yang menghambat. Ini mencegah penyalahgunaan berulang sambil tetap transparan.

**2. Penyensoran di lapisan modul, bukan di lapisan tampilan.**
`identity._mask()` menyensor NIK/NPWP/telepon sebelum keluar dari modul. Antarmuka tidak pernah menerima nilai utuh, sehingga kebocoran lewat log atau tangkapan layar tidak mungkin terjadi.

**3. Tingkat keyakinan eksplisit.**
Kandidat lokasi diberi bobot: 0.95 (koordinat metadata), 0.55 (bahasa OCR), 0.3 (tipe lanskap). Laporan hanya boleh memuat klaim ≥ 0.55. Ini memisahkan bukti dari dugaan.

**4. Bukti tidak pernah dimodifikasi.**
Gambar hanya dibaca; hash dihitung sebelum dan sesudah. Rantai kustodi mencatat hash, aktor, tujuan, dan waktu.

**5. Tanpa ketergantungan layanan berbayar.**
Semua inti berjalan lokal dan offline. Tautan pencarian balik hanya URL yang dibuka manual analis, sehingga tidak ada data yang dikirim otomatis ke pihak ketiga.

## Tabel modul

| Modul | Tanggung jawab | Fungsi kunci |
| --- | --- | --- |
| `forensics.py` | Baca properti teknis berkas | `analyze()`, `_extract_gps()`, `_device_fingerprint()`, `_ela()`, `_perceptual_hashes()` |
| `geolocate.py` | Ubah bukti jadi kandidat lokasi | `geolocate()`, `_solar_elevation()`, `_color_stats()` |
| `identity.py` | Ekstraksi & pivot pengenal | `pivot()`, `extract_identifiers()`, `_mask()` |
| `guardrails.py` | Kepatuhan & audit | `screen_request()`, `log_audit()`, `chain_of_custody()` |
| `report.py` | Perakit laporan | `build_report()`, `to_markdown()` |
| `main.py` | API HTTP | `POST /api/analyze` |

## Skor risiko kebocoran

| Bobot | Pemicu |
| --- | --- |
| +40 | Koordinat GPS tertanam |
| +15 | Make/Model perangkat terbaca |
| +15 | Nomor seri bodi kamera |
| +10 | Waktu pengambilan asli |
| +10 | Teks terbaca (OCR) |
| +10 | Sidik jari tabel kompresi |

Pita: KRITIS ≥ 70, TINGGI ≥ 45, SEDANG ≥ 25, RENDAH < 25.

Skor ini dipakai sebagai metrik kesadaran: makin tinggi, makin mudah foto itu mengungkap lokasi dan pemiliknya. Berguna untuk kampanye edukasi keamanan digital satuan.

## Batasan yang diketahui

- **Geolokasi visual tidak otomatis.** Penentuan lokasi dari lanskap tetap memerlukan penilaian analis; sistem menyediakan petunjuk dan tautan, bukan kesimpulan.
- **OCR bergantung pada tesseract.** Bila tidak terpasang, modul menandai `available: false` dan pipeline tetap berjalan.
- **Pencarian balik tidak diotomatiskan** karena mesin-mesin tersebut melarang akses program dan akan menimbulkan masalah hukum.
- **ELA bukan bukti definitif.** ELA menunjukkan perbedaan residu kompresi; gambar yang dikompres ulang berkali-kali bisa memberi positif palsu.

## Pengembangan lanjutan

1. Antrean tugas (Celery/RQ) untuk batch gambar.
2. Deteksi OCR multi-bahasa + pencocokan papan nama jalan ke basis data OSM.
3. Model pengenalan lanskap lokal (offline) untuk menggantikan heuristik warna.
4. Tanda tangan kriptografis laporan (Ed25519) agar hasil tidak dapat diubah setelah keluar.
5. Mode multi-pengguna dengan peran dan pemisahan kasus.
