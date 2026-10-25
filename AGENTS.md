# Catatan Repositori

## Ringkasan
TITIK TERANG — platform OSINT gambar (forensik EXIF/GPS, verifikasi autentisitas, geolokasi
heuristik, pivot identitas lawful, indeks hash lokal, mode batch).
Dibuat untuk Kartika Cyber Hackathon 2026, kategori 04 Cognitive Domain / 03 Core Infra.

## Perintah
- Jalankan server: `python3 -m uvicorn app.main:app --host 0.0.0.0 --port 12000`
- Uji: `python3 -m pytest tests -q`
- CLI: `python3 -m app.cli --help` (analyze, batch, index, similar, verify, purposes)
- Pasang dependensi: `pip install -r requirements.txt`; OCR butuh `apt-get install -y tesseract-ocr`

## Peta modul
- `app/forensics.py` — EXIF, GPS, hash, fingerprint perangkat, ELA, OCR
- `app/verify.py` — skor autentisitas, riwayat kompresi, asal platform, deteksi AI
- `app/geolocate.py` — kandidat lokasi, elevasi matahari, statistik warna
- `app/reverse_search.py` — indeks hash perseptual lokal, buku kerja, rantai atribusi
- `app/batch.py` — analisis massal + agregasi + CSV
- `app/identity.py` — ekstraksi pengenal + penyensoran
- `app/guardrails.py` — gerbang kepatuhan, audit, rantai kustodi
- `app/report.py` — perakit laporan + Markdown
- `app/cli.py`, `app/main.py`, `app/static/` — antarmuka

## Konvensi
- Kode dan komentar berbahasa Indonesia; nama variabel/fungsi berbahasa Inggris.
- Modul `app/guardrails.py` wajib dilewati setiap permintaan analisis baru.
- Nilai pribadi sensitif (NIK, NPWP, telepon, plat) harus disensor di dalam modul, bukan di UI.
- Data kasus/audit/indeks disimpan di `data/` (tidak masuk git).

## Catatan teknis penting
- Pencocokan kemiripan memakai dHash & pHash; aHash mudah memberi positif palsu.
- Gambar dengan `detail_level < 0.05` (nyaris rata) harus ditandai tidak andal, bukan dilaporkan cocok.
- Tes memakai fixture yang me-reload modul setelah mengubah `OSINT_DATA_DIR`.

## Batas keras
Jangan tambahkan fitur yang menambang data pribadi, menembus sistem, menampilkan
identitas sensitif utuh, atau menjalankan pencarian wajah otomatis.
