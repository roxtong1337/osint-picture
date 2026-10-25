# Proposal Solusi — TITIK TERANG

**Kategori:** 04 Cognitive Domain (Siber Sosial) · 03 Core Infra (Digital Forensic Toolkit)

## 1. Masalah

Setiap hari, ribuan foto beredar di ruang siber Indonesia. Sebagian besar membawa jejak yang tidak disadari pengunggahnya:

- koordinat GPS presisi 5–50 meter;
- merek dan model ponsel, bahkan nomor seri kamera;
- waktu pengambilan yang persis;
- teks pada gambar: nama jalan, nomor rumah, nama instansi.

Jejak ini punya dua sisi. Bagi **penyidik dan jurnalis**, ini bukti berharga untuk memverifikasi lokasi dan waktu sebuah peristiwa. Bagi **pelaku kejahatan**, ini alat pengintaian. Masalahnya, hari ini alat yang mampu membaca jejak tersebut umumnya:

1. berbahasa Inggris dan tidak kontekstual dengan Indonesia;
2. tidak punya pagar etika — mudah dipakai untuk menguntit;
3. berbayar, daring, dan mengirim data ke luar negeri;
4. tidak menghasilkan bukti yang bisa dipertanggungjawabkan di persidangan.

## 2. Solusi

**TITIK TERANG** — platform analisis gambar yang mengubah satu foto menjadi laporan intelijen terstruktur, dengan kepatuhan sebagai fitur inti, bukan tempelan.

### Alur kerja

1. Analis memilih **tujuan sah** dan menandatangani pernyataan tanggung jawab.
2. Sistem mengekstrak metadata, GPS, sidik jari perangkat, dan sinyal manipulasi.
3. Sistem menyusun **kandidat lokasi berperingkat** beserta daftar periksa verifikasi dan tautan peta.
4. Sistem menyusun **rencana pivot identitas** ke sumber publik resmi, dengan penyensoran nilai sensitif.
5. Laporan keluar dalam Markdown/JSON + rantai kustodi + jejak audit.

## 3. Yang membedakan

| Aspek | Alat umum | TITIK TERANG |
| --- | --- | --- |
| Bahasa & konteks | Inggris | Indonesia, siap pakai untuk satuan |
| Pagar etika | Tidak ada | Gerbang tujuan + blokir niat stalking + audit |
| Data pribadi | Ditampilkan utuh | Disensor di lapisan modul |
| Ketergantungan | Layanan awan berbayar | Berjalan lokal, tanpa internet |
| Bukti | Tidak ada | Rantai kustodi + hash + ID kasus |
| Tingkat keyakinan | Tidak dibedakan | 0.95 / 0.55 / 0.35 / 0.10 eksplisit |
| Keaslian gambar | Tidak dinilai | Skor autentisitas + asal platform + deteksi AI |
| Gambar dipakai ulang | Tidak terdeteksi | Indeks hash perseptual lokal, tanpa internet |
| Kelayakan laporan | Tidak ada aturan | Wajib ≥2 sumber independen + keyakinan ≥0.55 |
| Analisis massal | Satu per satu | Batch 200 gambar + rekomendasi + CSV |

## 4. Pemenuhan kriteria penilaian

### Relevansi dan Manfaat (25%)

Menjawab kebutuhan langsung: verifikasi konten untuk penindakan disinformasi, pemeriksaan barang bukti digital, dan audit kebocoran data di lingkungan satuan. Metrik **skor risiko kebocoran** dapat langsung dipakai untuk kampanye kesadaran keamanan digital prajurit.

### Inovasi Teknis (25%)

- **Geolokasi berlapis:** koordinat metadata + zona waktu dari bujur + validasi elevasi matahari (mendeteksi koordinat/waktu palsu) + statistik warna lanskap.
- **Kepatuhan sebagai arsitektur:** gerbang keputusan sebelum analisis, penyensoran di dalam modul, jejak audit append-only.
- **Tingkat keyakinan eksplisit** yang memisahkan bukti dari dugaan.
- **Verifikasi autentisitas:** skor 0–100 dari riwayat kompresi, residu ELA, dan sinyal perangkat; mendeteksi asal platform (WhatsApp/Instagram) dan media generatif.
- **Indeks hash perseptual lokal:** mendeteksi gambar hoaks yang dipakai ulang **tanpa internet** — penting untuk lingkungan satuan yang tertutup.
- **Buku kerja atribusi:** temuan dicatat per mesin, dan laporan hanya boleh keluar bila ada ≥2 sumber independen.

### Fungsionalitas Purwarupa (25%)

Purwarupa sudah berjalan. 32 tes otomatis lulus, mencakup ekstraksi GPS, hash perseptual, penyensoran NIK, blokir niat stalking, deteksi asal platform, deteksi media generatif, dedup indeks, penolakan gambar rata, rantai atribusi, agregasi batch, dan laporan end-to-end. Antarmuka web lengkap dengan unggah seret-lepas, dasbor hasil, mode batch, dan unduhan laporan. Tersedia juga CLI.

### Kelayakan Implementasi (15%)

- Berjalan lokal, tanpa ketergantungan awan — sesuai lingkungan satuan yang tertutup.
- Instalasi satu perintah; OCR opsional.
- Sudah berbentuk API, siap diintegrasikan ke sistem lain.
- Tidak butuh perangkat keras khusus.

### Kualitas Dokumentasi (10%)

README, dokumen arsitektur, kebijakan etika, proposal ini, plus laporan Markdown yang dihasilkan otomatis.

## 5. Contoh kasus nyata

**Kasus A — verifikasi unggahan hoaks.** Sebuah akun menyebar foto "kerusuhan di kota X". Analis mengunggah foto. Sistem menemukan GPS tertanam di kota berbeda, 400 km dari klaim, plus penanda perangkat lunak penyunting. Klaim terbantahkan dalam hitungan menit.

**Kasus B — kesadaran keamanan digital.** Satuan mengunggah 200 foto prajurit ke sistem. Skor risiko menunjukkan 62% foto membawa koordinat GPS. Hasilnya menjadi dasar kampanye pelatihan dan prosedur baru sebelum unggah.

**Kasus C — respons insiden.** Seorang pelaku mengirim foto "bukti" ke korban. Foto itu memuat nomor seri kamera dan koordinat. Penyidik mendapat titik awal yang sah untuk permintaan resmi ke penyedia layanan.

**Kasus D — deteksi gambar daur ulang.** Tim pemantau menemukan foto "bencana hari ini" yang viral. Indeks hash lokal menunjukkan gambar itu sudah pernah diunggah 8 bulan sebelumnya dengan narasi berbeda. Klaim hoaks terbongkar tanpa akses internet.

**Kasus E — deteksi media AI.** Foto "pejabat melakukan tindak pidana" beredar. Sistem mendeteksi penanda perangkat lunak generatif dan skor autentisitas rendah. Tim menahan penyebaran sebelum menjadi krisis.

## 6. Batas yang kami pegang

Alat ini **tidak** menambang data pribadi, tidak menembus sistem, tidak menampilkan NIK utuh, dan tidak menjalankan pencarian wajah otomatis. Batas ini bukan kelemahan teknis — ini syarat agar alat dapat dipakai institusi negara tanpa melanggar UU 27/2022 (PDP) dan UU 19/2016 (ITE).

## 7. Peta jalan

| Fase | Isi |
| --- | --- |
| Babak 1 (kini) | Purwarupa berjalan: forensik, verifikasi autentisitas, geolokasi, pivot identitas, pencarian balik, mode batch, kepatuhan, laporan, CLI |
| Setelah final | Antrean batch asinkron, OCR multi-bahasa, pencocokan papan nama ke OpenStreetMap |
| Skala satuan | Mode multi-pengguna + peran, tanda tangan kriptografis laporan, integrasi SIEM |
| Riset lanjut | Model lanskap lokal offline, deteksi media generatif berbasis model, pencocokan wajah terverifikasi |

## 8. Rujukan hukum

- UU 27/2022 tentang Pelindungan Data Pribadi
- UU 19/2016 tentang perubahan UU 11/2008 tentang ITE
- UU 1/2023 (KUHP) — pasal privasi & pencemaran
- SOP penanganan barang bukti digital instansi

---

*Proposal ini disusun untuk Kartika Cyber Hackathon 2026.*
