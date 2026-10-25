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

## 4. Pemenuhan kriteria penilaian

### Relevansi dan Manfaat (25%)

Menjawab kebutuhan langsung: verifikasi konten untuk penindakan disinformasi, pemeriksaan barang bukti digital, dan audit kebocoran data di lingkungan satuan. Metrik **skor risiko kebocoran** dapat langsung dipakai untuk kampanye kesadaran keamanan digital prajurit.

### Inovasi Teknis (25%)

- **Geolokasi berlapis:** koordinat metadata + zona waktu dari bujur + validasi elevasi matahari (mendeteksi koordinat/waktu palsu) + statistik warna lanskap.
- **Kepatuhan sebagai arsitektur:** gerbang keputusan sebelum analisis, penyensoran di dalam modul, jejak audit append-only.
- **Tingkat keyakinan eksplisit** yang memisahkan bukti dari dugaan.
- **Analisis ELA + deteksi perangkat lunak generatif** untuk menandai gambar AI/palsu.

### Fungsionalitas Purwarupa (25%)

Purwarupa sudah berjalan. 12 tes otomatis lulus, mencakup ekstraksi GPS, hash perseptual, penyensoran NIK, blokir niat stalking, kewajiban pernyataan, dan laporan end-to-end. Antarmuka web lengkap dengan unggah seret-lepas, dasbor hasil, dan unduhan laporan.

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

## 6. Batas yang kami pegang

Alat ini **tidak** menambang data pribadi, tidak menembus sistem, tidak menampilkan NIK utuh, dan tidak menjalankan pencarian wajah otomatis. Batas ini bukan kelemahan teknis — ini syarat agar alat dapat dipakai institusi negara tanpa melanggar UU 27/2022 (PDP) dan UU 19/2016 (ITE).

## 7. Peta jalan

| Fase | Isi |
| --- | --- |
| Babak 1 (kini) | Purwarupa berjalan: forensik, geolokasi, pivot identitas, kepatuhan, laporan |
| Setelah final | Antrean batch, OCR multi-bahasa, pencocokan papan nama ke OpenStreetMap |
| Skala satuan | Mode multi-pengguna + peran, tanda tangan kriptografis laporan, integrasi SIEM |
| Riset lanjut | Model lanskap lokal offline, deteksi media generatif berbasis model |

## 8. Rujukan hukum

- UU 27/2022 tentang Pelindungan Data Pribadi
- UU 19/2016 tentang perubahan UU 11/2008 tentang ITE
- UU 1/2023 (KUHP) — pasal privasi & pencemaran
- SOP penanganan barang bukti digital instansi

---

*Proposal ini disusun untuk Kartika Cyber Hackathon 2026.*
