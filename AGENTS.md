# Catatan Repositori

## Ringkasan
TITIK TERANG — platform OSINT gambar (forensik EXIF/GPS, geolokasi heuristik, pivot identitas lawful).
Dibuat untuk Kartika Cyber Hackathon 2026, kategori 04 Cognitive Domain / 03 Core Infra.

## Perintah
- Jalankan server: `python3 -m uvicorn app.main:app --host 0.0.0.0 --port 12000`
- Uji: `python3 -m pytest tests -q`
- Pasang dependensi: `pip install -r requirements.txt`; OCR butuh `apt-get install -y tesseract-ocr`

## Konvensi
- Kode dan komentar berbahasa Indonesia; nama variabel/fungsi berbahasa Inggris.
- Modul `app/guardrails.py` wajib dilewati setiap permintaan analisis baru.
- Nilai pribadi sensitif (NIK, NPWP, telepon, plat) harus disensor di dalam modul, bukan di UI.
- Data kasus/audit disimpan di `data/` (tidak masuk git).

## Batas keras
Jangan tambahkan fitur yang menambang data pribadi, menembus sistem, menampilkan
identitas sensitif utuh, atau menjalankan pencarian wajah otomatis.
