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
[Verifikasi] skor autentisitas · riwayat kompresi ·
             asal platform · deteksi media generatif
        │
        ▼
[Analisis Media] deteksi wajah (objek) · anomali tempelan
                 (rasio ELA) · deepfake · jejak antarmuka
        │
        ▼
[Geolokasi] koordinat → peta, zona waktu, elevasi matahari,
            statistik warna, kandidat berperingkat, daftar periksa
        │
        ▼
[Pencarian Balik] indeks hash lokal → kemiripan,
                  rencana pivot berurutan, buku kerja temuan
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
| `verify.py` | Nilai keaslian & asal gambar | `verify()`, `_recompression_estimate()`, `_platform_origin()`, `_ai_generation_indicators()` |
| `media_forensics.py` | Deteksi manipulasi media | `detect_faces()`, `analyze_face_anomalies()`, `deepfake_signals()`, `social_media_traces()` |
| `geolocate.py` | Ubah bukti jadi kandidat lokasi | `geolocate()`, `_solar_elevation()`, `_color_stats()` |
| `reverse_search.py` | Kemiripan & buku kerja pivot | `find_similar()`, `index_image()`, `pivot_plan()`, `record_finding()`, `attribution_chain()` |
| `batch.py` | Analisis massal & agregasi | `analyze_many()`, `analyze_folder()`, `to_csv()` |
| `identity.py` | Ekstraksi & pivot pengenal | `pivot()`, `extract_identifiers()`, `_mask()` |
| `guardrails.py` | Kepatuhan & audit | `screen_request()`, `log_audit()`, `chain_of_custody()` |
| `report.py` | Perakit laporan | `build_report()`, `to_markdown()` |
| `cli.py` | Antarmuka baris perintah | `main()` |
| `main.py` | API HTTP | `POST /api/analyze`, `POST /api/batch` |

## Skor autentisitas

Kebalikan dari skor risiko: makin tinggi, makin meyakinkan gambar asli.

| Bobot | Pemicu |
| --- | --- |
| −25 | EXIF kosong |
| −10 | Tanpa GPS |
| −25 | Indikasi kompresi ulang/penyuntingan |
| −10 | Sinyal anti-forensik |
| −30 / −15 | Indikasi kuat / sedang media generatif |
| −10 | Residu ELA tinggi |

Pita: TINGGI ≥ 75, SEDANG ≥ 50, RENDAH ≥ 30, SANGAT RENDAH < 30.

## Kemiripan gambar (indeks lokal)

Gambar yang dianalisis disimpan sebagai aHash/dHash/pHash. Pencarian kemiripan
memakai **dHash dan pHash** sebagai penentu; aHash hanya pelengkap karena mudah
memberi positif palsu pada gambar datar.

- jarak ≤ 2 → sangat mirip (kemungkinan gambar yang sama)
- jarak ≤ 6 → mirip (versi kompresi/crop ringan)
- gambar nyaris rata (`detail_level < 0.05`) → hasil ditandai **tidak andal** dan kemiripan diabaikan

Pencocokan berjalan tanpa internet, sehingga dapat dipakai di lingkungan tertutup
untuk mendeteksi gambar hoaks yang dipakai ulang.

## Deteksi manipulasi media

Modul `media_forensics.py` menangani sisi pertahanan: membuktikan gambar **palsu**.
Modul ini tidak melakukan pengenalan wajah, tidak membuat template biometrik, dan
tidak mencari identitas siapa pun.

**Anomali wajah (rasio ELA).** Wilayah wajah dibandingkan dengan latar memakai
Error Level Analysis. Rasio ≈ 1 berarti wajah menyatu dengan latar.

| Rasio ELA | Tafsir | Kecurigaan |
| --- | --- | --- |
| < 0.70 | penghalusan/retouch, atau wajah hasil render | 0.45 |
| 0.70 – 1.45 | wajar | 0 |
| > 1.45 | penajaman atau tempelan berkompresi berbeda | 0.35 |

Wilayah yang dihitung adalah bagian **dalam** kotak wajah (35% tepi dibuang), karena
kotak detektor Haar lebih longgar dari wajah sebenarnya.

**Batas yang diakui.** Metode ini andal untuk penghalusan, dan **lemah** terhadap
pergeseran kecerahan halus, kompresi ulang ganda, serta penajaman halus. Bila latar
pembanding kurang dari 10% gambar atau nyaris rata, hasilnya dinyatakan
`TIDAK DAPAT DINILAI` — bukan `RENDAH` — agar tidak menyesatkan.

**Jejak antarmuka.** Modul mengembalikan `ui_confidence` bertingkat, bukan klaim biner:
≥ 0.70 kemungkinan besar tangkapan layar, 0.50–0.69 belum konklusif (periksa manual),
< 0.50 diabaikan. Sinyal bilah status, watermark sudut, dan garis vertikal hanya dihitung
pada gambar **portrait**, karena pada foto lanskap sinyal itu hampir selalu hanya langit,
tanah, atau horizon. Foto lanskap dan foto biasa yang diuji menghasilkan `ui_confidence`
0.00, sedangkan tangkapan layar portrait 0.85.

## Aturan kelayakan laporan

Rantai atribusi hanya berstatus **SIAP DILAPORKAN** bila ada ≥2 sumber independen
(mesin berbeda) dan minimal satu temuan dengan keyakinan ≥0.55.

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


## Pencarian daring (`osint_online.py`)

Modul ini adalah satu-satunya bagian yang **mengirim data ke luar**. Karena itu ia tidak
pernah dijalankan secara otomatis: analis harus mencentang pencarian daring, dan setiap
panggilan tercatat di jejak audit.

| Layanan | Fungsi | Hasil yang dapat dibaca mesin |
| --- | --- | --- |
| Yandex Images | Pencarian gambar balik (unggah berkas) | Ya — halaman sumber + label objek |
| Google Lens | Pencarian gambar balik (unggah berkas) | Tidak — hanya tautan hasil |
| OSM Nominatim | Geokode balik (koordinat → alamat) | Ya |
| OSM Nominatim | Pencarian tempat (teks papan nama → koordinat) | Ya |

**Alur Yandex.** Unggah gambar → API mengembalikan `cbirId` → ambil halaman hasil →
urai bagian `CbirSitesList` (halaman yang memuat gambar) dan `CbirTags` (label objek).

**Mengapa Google Lens tidak diurai.** Google merender hasil dengan JavaScript, sehingga
HTML yang diterima tidak memuat data hasil. Modul mengembalikan tautan siap buka dan
menyatakan `parseable: false` — lebih jujur daripada menebak.

**Batas yang diakui.**
- Label objek Yandex sering muncul dalam bahasa Rusia atau Inggris.
- Hasil bergantung pada gambar pernah dipublikasikan; gambar tertutup tidak akan ketemu.
- Nominatim membatasi laju permintaan; modul memberi jeda otomatis 1,1 detik.
- Pencarian wajah daring **tidak** dijalankan, hanya pencarian objek dan sumber.


### Akurasi lokasi dari papan nama

Rantainya: OCR membaca teks pada gambar → baris nama jalan dan baris wilayah
digabung → singkatan dinormalkan → dicari ke Nominatim → hasil terbaik dipilih.

Dua hal yang membuat rantai ini sempat putus:

1. **Singkatan.** `JL. ASIA AFRIKA NO. 12` gagal di Nominatim, sedangkan
   `Jalan Asia Afrika` berhasil. Singkatan Indonesia dinormalkan lebih dulu,
   dan nomor rumah/RT/RW dibuang.
2. **Jalan tanpa kota.** `Jalan Asia Afrika` saja cocok ke Jakarta, padahal
   papan nama di gambar menyebut `KEC. SUMUR BANDUNG`. Baris jalan dan baris
   wilayah kini digabung menjadi satu kueri.

**Soal keraguan.** Kecocokan teks yang tinggi hanya berarti namanya sama, bukan
bahwa lokasinya unik. `Jalan Sudirman` cocok sempurna di puluhan kota. Karena
itu keraguan ditentukan oleh ada/tidaknya nama kecamatan/kota pada teks, bukan
oleh skor kecocokan. Kandidat tanpa konteks wilayah diberi keyakinan 0.4 dan
ditandai lemah.

**Soal deteksi bahasa.** Penanda dicocokkan dengan batas kata. Sebelumnya `kec`
cocok di dalam `KECELAKAAN`, dan kata `buka` (yang juga dipakai di Malaysia)
membuat papan nama Indonesia dilabeli Malaysia. Kini penanda dibagi kuat dan
lemah, dengan skor minimum agar satu kata bersama tidak menentukan kesimpulan.


## Analisis AI penglihatan (`ai_vision.py`)

Kode dapat membaca metadata dan mencari kemiripan, tetapi tidak dapat memahami
isi gambar. Model penglihatan menutup celah itu: membaca tulisan pada papan
nama, mengenali gaya arsitektur, menandai landmark, dan menyimpulkan wilayah.

Penyedia dipilih otomatis dari variabel lingkungan, sehingga alat tidak terkunci
pada satu vendor:

| Variabel | Penyedia |
| --- | --- |
| `OPENAI_API_KEY` | OpenAI |
| `GEMINI_API_KEY` atau `GOOGLE_API_KEY` | Google Gemini |
| `ANTHROPIC_API_KEY` | Anthropic |
| `OSINT_AI_API_KEY` + `OSINT_AI_BASE_URL` | Endpoint sendiri (Ollama, LM Studio, OpenRouter) |

**Alur.** Gambar diperkecil ke sisi terpanjang 1280 piksel (menjaga biaya token),
diubah ke base64, dikirim bersama prompt yang meminta JSON. Jawaban diurai,
disaring, lalu kandidat lokasinya dicari koordinatnya lewat Nominatim agar dapat
ditampilkan di peta.

**Batas identitas.** Prompt melarang model mengidentifikasi orang. Karena prompt
saja tidak cukup, hasilnya disaring dua lapis:

1. Hanya bidang di daftar putih yang dipertahankan.
2. Setiap bidang diperiksa pola data pribadi: surel, NIK 16 digit, nomor telepon
   Indonesia, nama akun media sosial, alamat IP. Bidang yang memuatnya dibuang
   dan diganti catatan penolakan.

Pencocokan kata kunci memakai batas kata. Tanpa itu `nik` cocok di dalam
`ikonik` dan `nama` cocok di dalam `dinamakan`, sehingga peringatan identitas
muncul pada hasil yang bersih.

**Batas yang diakui.** Model dapat salah dan tetap percaya diri. Karena itu setiap
kandidat ditandai "dugaan model penglihatan — wajib diverifikasi ke sumber asli",
dan kandidat dengan keyakinan di bawah 0,6 ditandai ambigu. Model juga boleh
menjawab `cannot_determine`, dan jawaban itu ditampilkan apa adanya.
