# Kebijakan Etika & Kepatuhan

## Prinsip dasar

Analisis gambar menyentuh privasi orang. Alat ini dibangun di atas tiga prinsip:

1. **Tujuan sah lebih dulu.** Tidak ada analisis tanpa tujuan yang dapat dipertanggungjawabkan.
2. **Minimum yang diperlukan.** Hanya data yang benar-benar terlihat pada gambar yang diproses; tidak ada penambangan data pribadi.
3. **Dapat diaudit.** Setiap permintaan tercatat: siapa, kapan, untuk apa, dan diputuskan apa.

## Tujuan yang diizinkan

| ID | Tujuan |
| --- | --- |
| `penegakan_hukum` | Penyelidikan pidana dengan kewenangan resmi |
| `verifikasi_jurnalistik` | Verifikasi fakta & atribusi sumber |
| `penelitian` | Riset akademik dengan tinjauan etik |
| `ctf_pelatihan` | Latihan CTF, kelas, pelatihan keamanan siber |
| `uji_ketahanan_sendiri` | Uji ketahanan atas aset organisasi sendiri |
| `respons_insiden` | Investigasi insiden pada sistem sendiri |
| `forensik_digital` | Pemeriksaan barang bukti digital yang sah |
| `perlindungan_anak` | Perlindungan anak / orang hilang bersama pihak berwenang |

## Yang ditolak otomatis

Permintaan dengan indikasi berikut ditolak dan dicatat:

- pengawasan orang tanpa dasar (melacak mantan/pasangan, stalking);
- doxing, penyebaran, atau jual-beli data pribadi;
- akses ilegal ke akun atau sistem orang lain;
- penyadapan tanpa kewenangan.

Selain itu, sistem memberi peringatan bila mendeteksi kemungkinan target sensitif (objek militer, pejabat, infrastruktur kritis). Hasil untuk target semacam itu hanya boleh beredar di kanal internal berwenang.

## Penanganan data pribadi

- **NIK, NPWP, nomor telepon, dan plat nomor disensor** di dalam modul sebelum keluar. Analis melihat bentuk tersamarkan, bukan nilai utuh.
- Tidak ada pencarian otomatis ke basis data pribadi atau layanan berbayar penyingkap identitas.
- Pencarian wajah tidak dijalankan otomatis; sistem hanya menyediakan tautan, dan penggunaannya dibatasi untuk tujuan dengan dasar hukum kuat.
- Tidak ada data yang dikirim ke layanan pihak ketiga. Seluruh inti berjalan lokal.

## Kepatuhan hukum Indonesia

Rujukan utama:

- **UU 27/2022 tentang Pelindungan Data Pribadi** — pemrosesan wajib punya dasar hukum dan tujuan terbatas.
- **UU 19/2016 (perubahan UU 11/2008) tentang ITE** — larangan akses tanpa hak dan penyadapan.
- **UU 1/2023 (KUHP)** — pasal tentang pencemaran nama baik dan penyerangan privasi.
- **Peraturan Kapolri / SOP instansi** untuk penanganan barang bukti digital.

Alat ini dirancang sebagai instrumen **pemeriksaan**, bukan pengumpulan data. Analis tetap bertanggung jawab penuh atas legalitas tindakannya.

## Kebijakan tingkat keyakinan

| Tingkat | Dasar | Boleh masuk laporan? |
| --- | --- | --- |
| 0.95 | Pengenal langsung dari metadata/dokumen resmi | Ya |
| 0.55 | Pola kuat: email + akun aktif + organisasi sama | Ya |
| 0.35 | Hanya nama atau hanya kemiripan wajah | Tidak, indikatif saja |
| 0.10 | Dugaan tanpa verifikasi | Tidak |

Aturan pelaporan: klaim wajib ≥ 0.55 dan sumbernya harus dapat dibuka ulang oleh pihak lain.

## Rantai kustodi

Setiap analisis mencatat:

- SHA-256 berkas bukti;
- nama analis;
- tujuan;
- waktu akuisisi.

Berkas tidak pernah dimodifikasi. Bandingkan hash sebelum dan sesudah pemeriksaan untuk membuktikan keutuhan bukti.

## Untuk penilaian hackathon

Kategori **04 Cognitive Domain** menuntut kemampuan memantau dan menganalisis ruang siber sosial. TITIK TERANG menjawab kebutuhan itu dari sisi pertahanan: bukan alat untuk mengintai warga, tetapi alat untuk **memverifikasi** konten, mengukur kebocoran data, dan menegakkan akuntabilitas — dengan pagar etika yang bisa ditunjukkan ke pengadilan.


## Pencarian daring dan privasi

Pencarian daring bersifat **opt-in**. Bila diaktifkan, gambar dikirim ke Yandex dan/atau
Google, dan koordinat dikirim ke OpenStreetMap. Ini berarti:

- Jangan aktifkan pencarian daring untuk materi rahasia, bukti yang belum boleh
  dipublikasikan, atau gambar yang memuat data pribadi sensitif.
- Aksi ini tercatat di jejak audit beserta nama analis dan tujuan.
- Pencarian **wajah** daring tidak dijalankan oleh alat ini. Yang dijalankan hanya
  pencarian objek dan atribusi sumber.
- Hasil pencarian balik adalah petunjuk, bukan bukti. Wajib diverifikasi ke sumber asli.


## AI penglihatan dan identitas

Analisis AI bersifat **opt-in**. Bila diaktifkan, gambar dikirim ke penyedia
model AI pihak ketiga.

Alat ini **tidak** mengidentifikasi orang. Yang dilakukan model hanya membaca
isi gambar untuk menentukan tempat. Larangan itu ditegakkan di tiga tempat:
prompt melarangnya, daftar bidang membatasi keluaran, dan penyaring pola
membuang data pribadi (surel, NIK, nomor telepon, nama akun).

Model tetap bisa salah. Setiap kandidat ditandai sebagai dugaan yang wajib
diverifikasi ke sumber asli, dan model boleh menjawab bahwa lokasi tidak dapat
ditentukan.
