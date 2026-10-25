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
- `app/media_forensics.py` — deteksi wajah (objek saja), anomali tempelan via rasio ELA, deepfake, jejak UI
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
- `app/media_forensics.py` memakai OpenCV 4.x (`<5`); OpenCV 5 menghapus `CascadeClassifier`.
  Berkas cascade ada di `app/cascades/`, diunduh dari repo resmi OpenCV.
- Rasio ELA memakai wilayah DALAM kotak wajah (`INNER_INSET`); kotak Haar lebih longgar
  dari wajah sebenarnya sehingga tepinya mengencerkan sinyal.
- Bila latar pembanding terlalu sempit/rata, kembalikan `TIDAK DAPAT DINILAI`, jangan `RENDAH`.
- Sinyal jejak UI hanya dihitung pada gambar portrait (`h > w * 1.15`). Foto lanskap dengan
  langit/tanah polos akan memberi positif palsu bila syarat ini dilepas.

## Batas keras
Jangan tambahkan fitur yang menambang data pribadi, menembus sistem, menampilkan
identitas sensitif utuh, atau menjalankan pencarian wajah otomatis.

- Modul `osint_online.py` adalah satu-satunya yang mengirim data ke luar. Jangan pernah
  memanggilnya tanpa `payload["online_lookup"]` yang benar-benar diset analis.
- Google Lens tidak dapat diurai (hasil dirender JavaScript). Jangan menambahkan parser
  HTML untuk Lens; kembalikan tautan dan nyatakan `parseable: false`.
- Yandex diuji lewat `tests/fixtures/yandex_cbir_sample.html` (HTML asli). Bila struktur
  halaman Yandex berubah, perbarui fixture itu, jangan melemahkan asersi.
- `tests/test_osint_online.py` memakai pembungkus `_http_get`/`_http_post`. Tes tidak
  boleh menyentuh jaringan; gunakan monkeypatch pada kedua pembungkus itu.

- Penanda bahasa dan wilayah HARUS dicocokkan dengan batas kata
  (`_marker_present`). Tanpa itu `kec` cocok di dalam `KECELAKAAN`.
- Keraguan lokasi ditentukan oleh ada/tidaknya nama kecamatan/kota pada teks,
  bukan oleh skor kecocokan teks. `Jalan Sudirman` cocok sempurna di puluhan kota.
- `_has_region_context` hanya menghitung penanda administratif. Kata `kota` dan
  `desa` sengaja dikecualikan karena sering menjadi bagian nama jalan
  (`Jalan Kota Baru`).

- `ai_vision.py` mengirim gambar ke penyedia pihak ketiga. Jangan pernah
  memanggilnya tanpa `payload["ai_vision"]` yang diset analis.
- Batas identitas ditegakkan dua lapis: daftar bidang diizinkan + penyaring pola
  data pribadi. Jangan melonggarkan salah satunya. Prompt saja tidak cukup.
- Pencocokan kata kunci identitas WAJIB memakai batas kata. Tanpa itu `nik`
  cocok di dalam `ikonik` dan memicu peringatan palsu.
- Model boleh menjawab `cannot_determine`. Jangan memaksa alat menebak saat
  model menyatakan bukti kurang.
