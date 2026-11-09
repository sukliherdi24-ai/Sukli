# LMS SMAN 9 Wajo

Aplikasi pembelajaran berbasis PHP dan MySQL untuk admin, guru, dan siswa.

## Menjalankan di XAMPP

1. Salin folder proyek ke `C:\xampp\htdocs\Latihan_LMS`.
2. Jalankan Apache dan MySQL dari XAMPP.
3. Buka phpMyAdmin (`http://localhost/phpmyadmin`), pilih **Import**, lalu impor `database.sql`.
4. Buka `http://localhost/Latihan_LMS/`. Pengaturan koneksi default: host `127.0.0.1`, database `lms_sman9_wajo`, user `root`, tanpa password. Sesuaikan konstanta DB di `bootstrap.php` bila konfigurasi MySQL berbeda.
5. Login dengan akun demo:

   | Peran | Username | Password |
   |---|---|---|
   | Admin | `admin` | `admin` |
   | Guru | `guru` | `guru` |
   | Siswa | `siswa` | `siswa` |

Akun demo dan mata pelajaran Matematika untuk kelas X MIPA 1 dibuat otomatis saat aplikasi pertama kali dibuka. Password disimpan sebagai hash. Ganti password demo sebelum digunakan pada lingkungan publik.

## Fitur

- **Admin:** membuat kelas dan akun, menonaktifkan/mengaktifkan akun, serta mengelola mata pelajaran dan guru pengampu.
- **Admin:** mengedit identitas/akun pengguna, mengubah nama kelas dan menghapus kelas kosong, serta mengedit data mata pelajaran.
- **Guru:** menambahkan dan mengedit materi/tugas, melihat pengumpulan siswa, mengunduh jawaban, serta memberi nilai dan umpan balik.
- **Siswa:** melihat materi dan tugas untuk kelasnya, mengumpulkan atau mengganti file tugas, serta melihat nilai dan umpan balik.
- **Semua peran:** mengedit nama dan username sendiri, serta mengganti password dengan konfirmasi password saat ini.
- Kelas yang masih memiliki pengguna atau mata pelajaran tidak dapat dihapus. Pindahkan data terkait terlebih dahulu agar catatan pembelajaran tidak hilang.
- Upload menerima PDF, dokumen Office, JPG, dan PNG dengan batas 10 MB. File disimpan dengan nama acak dan tidak dapat diakses langsung melalui URL.
