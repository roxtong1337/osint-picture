# TITIK TERANG — Platform OSINT Gambar

Alat analisis gambar untuk **penegakan hukum, verifikasi jurnalistik, respons insiden, dan pelatihan keamanan siber**. Masukkan sebuah foto, keluar: metadata perangkat, koordinat GPS, kandidat lokasi berperingkat, sinyal manipulasi, dan rencana pivot identitas — lengkap dengan gerbang kepatuhan dan jejak audit.

Kategori lomba: **04 Cognitive Domain (Siber Sosial)** dan **03 Core Infra (Digital Forensic Toolkit)**.

---

## Mengapa ini penting

Foto adalah salah satu pembocor data terbesar. Satu foto jalan bisa memuat koordinat GPS, model ponsel, nomor seri kamera, dan waktu persis. Bagi penyidik dan jurnalis, informasi ini adalah bukti. Bagi pelaku kejahatan, ini alat pengintaian.

Karena itu TITIK TERANG dirancang **lawful-by-design**: setiap analisis wajib melewati gerbang tujuan sah + pernyataan tanggung jawab, dan setiap permintaan tercatat di jejak audit yang tidak dapat diubah.

## Fitur

| Kelompok | Kemampuan |
| --- | --- |
| Forensik berkas | MD5/SHA-1/SHA-256, dimensi, format, sidik jari tabel kuantisasi JPEG |
| Metadata | Semua tag EXIF, sub-IFD GPS/Exif, make/model/lensa, nomor seri kamera, waktu asli |
| Geolokasi | Koordinat GPS desimal + peta, zona waktu perkiraan, validasi elevasi matahari, statistik warna lanskap |
| Pencarian balik | Tautan 8 mesin (Google Lens, Yandex, Bing, TinEye, PimEyes, FaceCheck, Forensically, InVID) |
| Verifikasi lokasi | Daftar periksa geolokasi 6 langkah + petunjuk per tipe lanskap |
| Manipulasi | Error Level Analysis (ELA) + visualisasi, deteksi perangkat lunak penyunting/AI |
| Identitas | Ekstraksi email, telepon, URL, handle, NIK, NPWP, plat; **nilai sensitif disensor**; pivot ke sumber publik resmi |
| Kepatuhan | Gerbang tujuan, blokir niat stalking/doxing, peringatan target sensitif, kebijakan tingkat keyakinan |
| Bukti | Rantai kustodi (hash + aktor + waktu), jejak audit JSONL, ID kasus |
| Laporan | Markdown siap lampir proposal + JSON lengkap |

## Menjalankan

```bash
pip install -r requirements.txt
# OCR opsional (membaca teks pada gambar)
apt-get install -y tesseract-ocr

python3 -m uvicorn app.main:app --host 0.0.0.0 --port 12000
```

Buka `http://localhost:12000`. Uji cepat: `curl localhost:12000/healthz`.

## Uji

```bash
python3 -m pytest tests -q
```

12 tes mencakup: ekstraksi GPS/EXIF, hash stabil, hash perseptual, penalisasi skor saat metadata dihapus, urutan kandidat lokasi, penyensoran NIK, blokir niat stalking, kewajiban pernyataan tanggung jawab, dan laporan end-to-end.

## Arsitektur

```
app/
  forensics.py    # EXIF/GPS/hash/fingerprint perangkat/ELA/OCR
  geolocate.py    # kandidat lokasi + daftar periksa + tautan verifikasi
  identity.py     # ekstraksi pengenal + pivot lawful + penyensoran
  guardrails.py   # gerbang kepatuhan + jejak audit + rantai kustodi
  report.py       # perakit laporan + ekspor Markdown
  main.py         # API FastAPI
  static/         # antarmuka web
```

Alur: unggah → gerbang kepatuhan → forensik → geolokasi → pivot identitas → laporan + audit.

## API

| Metode | Jalur | Fungsi |
| --- | --- | --- |
| GET | `/api/purposes` | Daftar tujuan sah & deskriptor lanskap |
| POST | `/api/analyze` | Analisis lengkap (multipart) |
| POST | `/api/report/markdown` | Laporan Markdown langsung |
| GET | `/api/cases` | Daftar kasus |
| GET | `/api/cases/{id}` | Detail kasus |
| GET | `/healthz` | Status |

Contoh:

```bash
curl -X POST localhost:12000/api/analyze \
  -F image=@foto.jpg -F purpose=penegakan_hukum -F attestation=true \
  -F analyst_name="Penyidik A" -F descriptors=perkotaan,jalan_raya
```

Respons `403` bila gerbang kepatuhan menolak — namun hasil forensik teknis tetap dikembalikan agar analis memahami mengapa permintaan ditolak.

## Batas etika (bukan sekadar catatan kaki)

Alat ini **tidak**:
- membeli, menambang, atau membocorkan data pribadi;
- menembus sistem apa pun;
- menampilkan NIK/nomor telepon dalam bentuk utuh (selalu disensor);
- menjalankan pencarian wajah otomatis.

Alat ini **melakukan**: ekstraksi bukti, penyusunan tautan ke sumber publik resmi, dan pencatatan audit. Pencarian lanjutan tetap dilakukan manusia berwenang.

Baca [docs/ETIKA.md](docs/ETIKA.md) untuk kebijakan lengkap dan [docs/ARSITEKTUR.md](docs/ARSITEKTUR.md) untuk detail teknis.
