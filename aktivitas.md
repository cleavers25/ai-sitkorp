# Catatan Aktivitas — AI Infrastructure & Website Security Assistant

File ini mencatat setiap aktivitas analisis dan build, sebagai rujukan.
Format: tanggal, apa yang dikerjakan, keputusan, file yang berubah, dan langkah berikutnya.

---

## 2026-09-24 — Analisis awal PRD

**Yang dikerjakan**
- Membaca isi direktori `AI-Sitkorp/`. Isinya baru satu file: `AI-Infrastructure-Website-Security-Assistant-PRD.md` (PRD v1.0, 63 bagian). Belum ada kode sama sekali, dan direktori ini belum menjadi git repository.
- Memeriksa tool yang terpasang di mesin dev (Windows 11):
  - Docker 29.5.3, WSL 2.7.3
  - Python 3.12.10
  - Node v24.15.0, npm 11.12.1 (pnpm belum terpasang)
  - Git 2.54.0
  - PostgreSQL dan Redis belum terpasang secara native (bisa dijalankan lewat Docker)

**Ringkasan PRD**
- Tujuan: aplikasi internal on-premise untuk memantau, meng-assess, dan membackup 30+ website/server, dengan AI sebagai lapisan analisis (bukan eksekutor bebas).
- Stack yang direkomendasikan: Next.js + TS, FastAPI, PostgreSQL + pgvector, Redis + Celery, AsyncSSH, ClamAV/YARA/Wazuh, OpenBao/Vault, Docker Compose.
- Arsitektur: modular monolith + async workers.
- MVP dibagi 5 fase: Foundation → Assessment → AI → Automation → Advanced Security.

**Temuan analisis / hal yang perlu diputuskan**
- Cakupan PRD sangat luas; perlu ditentukan fase mana yang dibangun lebih dulu.
- Ada inkonsistensi kecil di PRD:
  - Bagian 5/27 menyebut role AUDITOR, tetapi tabel RBAC (bagian 44) tidak memuatnya.
  - Status check di bagian 40 memakai `WARNING`, sedangkan status asset memakai GREEN/YELLOW/RED; perlu pemetaan yang jelas.
  - Tabel RBAC: Security bisa Quarantine tanpa approval, padahal bagian 24 menggolongkan quarantine sebagai HIGH RISK (butuh approval).
  - Bagian 52 menyebut "100 assets" tetapi "500 websites"; angka website lebih besar dari asset, padahal website juga termasuk asset.
- Target deployment (OS server produksi) belum disebutkan; mesin dev saat ini Windows.
- Mekanisme ClamAV/YARA belum jelas: scan dijalankan di server target (via SSH) atau file ditarik ke server manajemen?
- Pilihan secret store (OpenBao vs enkripsi di level aplikasi) berpengaruh besar pada kompleksitas MVP.

**Status**: menunggu jawaban user atas pertanyaan klarifikasi sebelum mulai build.

---

## 2026-09-24 — Keputusan user (klarifikasi)

| Topik | Keputusan |
|---|---|
| Scope build pertama | **Fase 1 saja**: auth, RBAC, dashboard, CRUD asset/server/website, SSH connectivity, audit log, PostgreSQL, Redis |
| Penyimpanan credential | **Enkripsi di level aplikasi** (AES-GCM, master key dari env/file), dengan interface `SecretBackend` agar nanti bisa pindah ke OpenBao |
| AI provider awal | **OpenAI / OpenAI-compatible** dan **Anthropic (Claude)** (baru dipakai di Fase 3) |
| Lokasi scan malware | **Di server target** lewat SSH (baru dipakai di Fase 2) |

**Default yang diusulkan untuk inkonsistensi PRD** (belum dikonfirmasi user):
- Role AUDITOR: read-only ke asset dan audit log, tanpa hak eksekusi.
- Quarantine selalu butuh approval untuk semua role kecuali ADMIN (mengikuti bagian 24).
- Pemetaan status check ke asset: `PASS`→GREEN, `WARNING`→YELLOW, `FAIL`/`CRITICAL`→RED; status asset = status check terburuk.
- Target skala: 100 server + 500 website (total sekitar 600 asset).

---

## 2026-09-24 — Build Fase 1: Backend (FastAPI)

User menyetujui default di atas dengan "lanjut".

**Persiapan**
- `git init -b main` di root project.
- Docker Desktop belum berjalan (daemon mati), jadi backend dikembangkan dengan Python venv (`apps/api/.venv`), dan tes memakai SQLite in-memory.

**Struktur backend `apps/api/`**
| Path | Isi |
|---|---|
| `app/core/config.py` | Konfigurasi dari env var. `JWT_SECRET` (min. 32 karakter) dan `SECRET_MASTER_KEY` (base64 32 byte) wajib diisi |
| `app/core/enums.py` | Role, AssetType, AssetStatus (UNKNOWN/GREEN/YELLOW/RED), Severity, RiskLevel, ConnectivityStatus, CredentialKind |
| `app/core/rbac.py` | Matriks permission per role (turunan PRD bagian 44 + keputusan AUDITOR) |
| `app/core/security.py` | Hash password Argon2, JWT, aturan kekuatan password (min. 12 karakter, 3 jenis karakter) |
| `app/core/redaction.py` | Menyamarkan password, token, key, dan blok PEM sebelum masuk audit log |
| `app/models/` | `users`, `assets` (+ `servers`, `websites` via joined inheritance), `credential_references`, `encrypted_secrets`, `audit_logs` |
| `app/services/secrets.py` | Interface `SecretBackend` + `LocalEncryptedBackend` (AES-256-GCM, path diikat sebagai AAD) |
| `app/services/ssh_client.py` | Wrapper AsyncSSH: host key wajib di-pin, batas ukuran output, timeout |
| `app/services/connectivity.py` | Tes koneksi SSH: pin host key saat pertama kali (TOFU), baca OS/kernel, catat ke audit |
| `app/tools/registry.py` | Tool layer terkontrol. Tool pertama: `check_connectivity` (SAFE, command tetap `uname -srm` & `cat /etc/os-release`) |
| `app/worker/` | Celery app + task `server.check_connectivity` |
| `app/api/v1/` | Router: health, auth, users, credentials, assets/servers/websites/jobs, audit-logs, dashboard |
| `app/cli.py` | `python -m app.cli create-user ...` (password lewat prompt, tidak lewat argumen) |
| `alembic/versions/20260924_0001_initial_schema.py` | Migrasi awal + trigger PostgreSQL yang menolak UPDATE/DELETE di `audit_logs` |
| `tests/` | 40 tes pytest |

**Endpoint API (prefix `/api/v1`)**
- `GET /health`, `GET /health/ready`
- `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/change-password`
- `GET|POST /users`, `PATCH /users/{id}`, `POST /users/{id}/reset-password` (khusus ADMIN)
- `GET|POST /credentials`, `GET|DELETE /credentials/{id}`, `PUT /credentials/{id}/secret` (rotasi)
- `GET /assets` (filter type/status/q)
- `GET|POST /servers`, `GET|PATCH|DELETE /servers/{id}`, `POST /servers/{id}/test-connection`, `POST /servers/{id}/reset-host-key`
- `GET|POST /websites`, `GET|PATCH|DELETE /websites/{id}`
- `GET /jobs/{job_id}`, `GET /audit-logs`, `GET /dashboard/summary`

**Keputusan desain penting**
- **Sesi login**: JWT di cookie httpOnly + SameSite=strict (juga bisa lewat header Bearer). Logout dan ganti password menaikkan `token_version`, sehingga semua token lama user itu langsung tidak berlaku.
- **Brute-force**: akun dikunci 15 menit setelah 5 kali gagal login. Pesan error untuk email yang tidak ada dan password salah dibuat identik, supaya daftar email tidak bisa ditebak.
- **Admin terakhir**: sistem menolak menurunkan role atau menonaktifkan admin aktif terakhir.
- **Secret**: tidak pernah dikembalikan oleh API mana pun. Yang ditampilkan hanya fingerprint public key SSH.
- **Host key SSH**: di-pin saat koneksi pertama. Jika berubah, status menjadi `HOST_KEY_MISMATCH` dan koneksi diblokir sampai admin menekan "reset host key" (tercatat di audit sebagai HIGH risk). Ini untuk mencegah serangan man-in-the-middle.
- **Status asset**: tetap `UNKNOWN` sampai ada assessment (Fase 2). Hasil tes SSH disimpan terpisah di `connectivity_status`, supaya status GREEN tidak dipakai untuk sesuatu yang belum benar-benar diperiksa.

**Hasil verifikasi**
- `pytest`: **40 passed**.
- Alembic: upgrade → downgrade → upgrade berhasil di SQLite, dan `alembic check` tidak mendeteksi selisih dengan model. Migrasi di PostgreSQL belum diuji karena Docker belum berjalan.

---

## 2026-09-24 — Build Fase 1: Docker, Frontend (Next.js), dan verifikasi end-to-end

**Docker / deployment**
| File | Isi |
|---|---|
| `docker-compose.yml` | Service `postgres` (pgvector/pg16), `redis` (dengan password), `api`, `worker`, `web`, `reverse-proxy` (Caddy). **Hanya Caddy yang membuka port** (80/443); database dan Redis tidak bisa diakses dari luar |
| `apps/api/Dockerfile` + `docker-entrypoint.sh` | Image Python 3.12-slim, berjalan sebagai user non-root. Mode `api` otomatis menjalankan `alembic upgrade head`; mode `worker` menjalankan Celery |
| `apps/web/Dockerfile` | Build Next.js `standalone`, berjalan sebagai user non-root |
| `infrastructure/caddy/Caddyfile` | HTTPS internal (`tls internal`), security headers, `/api/*` → api, sisanya → web |
| `.env.example` | Template konfigurasi beserta cara generate secret |
| `.gitignore`, `.gitattributes` | `.env` tidak ikut ter-commit; file `.sh` dipaksa berakhiran baris LF |
| `README.md` | Cara menjalankan (Docker dan dev lokal) serta prinsip keamanan |

**Frontend `apps/web/`** (Next.js 15, TypeScript, Tailwind v4, shadcn/ui style `base-nova` berbasis Base UI, TanStack Query; UI berbahasa Indonesia)
| Halaman | Fungsi |
|---|---|
| `/login` | Login. Parameter `?next=` hanya menerima path relatif, untuk mencegah open redirect |
| `/` | Dashboard: total asset/server/website, distribusi status, konektivitas SSH, aktivitas terbaru (hanya untuk role yang punya `audit:view`) |
| `/servers`, `/servers/[id]` | Daftar dengan pencarian dan filter konektivitas; detail; tambah/ubah/hapus; **Tes koneksi** (status di-poll otomatis selama PENDING); peringatan dan tombol reset jika host key berubah |
| `/websites`, `/websites/[id]` | Daftar, detail, tambah/ubah/hapus, hubungkan ke server |
| `/credentials` | Tambah credential (SSH key/password/API key), rotasi secret, hapus. Secret tidak pernah ditampilkan |
| `/users` | Khusus ADMIN: tambah user, ubah role, aktifkan/nonaktifkan, reset password |
| `/audit` | Audit log dengan filter aksi/hasil, pagination, dan detail JSON |
| `/account` | Ganti password sendiri |
- Menu sidebar hanya menampilkan item sesuai permission role user.
- `middleware.ts` mengarahkan ke `/login` jika belum ada cookie sesi.
- Font memakai font sistem (bukan Google Fonts), supaya build tidak butuh internet di server on-prem.

**Catatan dependency**
- Komponen shadcn versi terbaru meng-import paket npm `cn`. Sudah diperiksa: paket itu resmi dari repo `shadcn-ui/cn`, maintainer-nya shadcn, dan tidak punya install script, jadi aman.

**Bug yang ditemukan dan diperbaiki saat uji end-to-end**
1. **Email domain internal ditolak**: `EmailStr` (library email-validator) menolak `admin@example.local` karena `.local` dianggap special-use domain. Validasi diganti dengan pengecekan format sederhana (`normalize_email`) yang menerima `.local`/`.internal`. Dependency `email-validator` dihapus, dan ditambahkan tes regresi.
2. **Proxy dev gagal**: Next.js me-resolve `localhost` ke IPv6 (`::1`), sedangkan uvicorn listen di `127.0.0.1`. Default proxy diubah ke `127.0.0.1:8000`.

**Hasil verifikasi**
- Backend `pytest`: **47 passed**. Termasuk 6 tes integrasi SSH sungguhan (tanpa mock) ke server AsyncSSH lokal: auth password, auth private key, host key yang di-pin salah → ditolak, password salah → ditolak, output terpotong sesuai batas, koneksi tanpa host key ter-pin → ditolak.
- Frontend: `tsc --noEmit` bersih, `eslint` bersih, `next build` sukses (11 route).
- Uji end-to-end lewat proxy Next.js (API + web berjalan lokal, SQLite, Celery eager):
  - akses tanpa login → 307 ke `/login`;
  - login admin bootstrap → cookie httpOnly terpasang;
  - buat credential → buat server → tes koneksi ke port tertutup → status `FAILED` dengan pesan error;
  - buat website yang terhubung ke server;
  - dashboard menampilkan angka yang benar;
  - audit log mencatat 6 aksi, dan secret tidak muncul di audit maupun di response API;
  - logout → token lama ditolak (401);
  - security headers terpasang;
  - semua 9 halaman UI merespons HTTP 200 saat login.

**Belum diverifikasi**
- `docker compose up` dan migrasi di PostgreSQL asli, karena Docker Desktop belum berjalan di mesin ini.
- Tampilan UI belum dicek secara visual di browser (baru dicek status HTTP-nya).
- Tes koneksi ke server Linux sungguhan di jaringan.

**Status acceptance criteria PRD (bagian 57) untuk Fase 1**
- [x] User bisa membuat server
- [x] User bisa membuat website
- [x] Website bisa dihubungkan ke server
- [x] Asset punya status
- [x] RBAC berjalan
- [x] Audit log ada
- [x] Secret tidak tercatat di log
- [x] AI tidak bisa menjalankan shell bebas (belum ada AI; tool layer hanya punya command tetap)
- [ ] Aksi high-risk butuh approval (approval workflow ada di Fase 4; saat ini aksi berisiko hanya bisa dilakukan role ADMIN/INFRA dan tercatat sebagai HIGH risk)

**Langkah berikutnya yang disarankan**
1. Jalankan Docker Desktop, lalu `docker compose up -d --build` untuk verifikasi di PostgreSQL + Redis + Celery asli.
2. Uji tes koneksi ke 1 server staging.
3. Mulai Fase 2 (assessment engine: health check, HTTP/SSL, ClamAV/YARA di server target, status GREEN/YELLOW/RED).

---

## 2026-09-24 — Fase 2 dimulai: rancangan Assessment Engine

User meminta "lanjut fase 2". Docker Desktop sekarang sudah berjalan, sehingga verifikasi di PostgreSQL/Redis asli bisa dilakukan.

**Cakupan Fase 2 (PRD bagian 56)**: server health, website health, HTTP, SSL, disk, service, process, basic malware scan, ClamAV, YARA, dan report assessment.

**Rancangan**
- Tabel baru:
  - `assessments`: satu kali assessment per asset, dengan status QUEUED/RUNNING/COMPLETED/FAILED dan overall GREEN/YELLOW/RED.
  - `assessment_checks`: hasil tiap check, dengan format standar PRD bagian 40 (check, status, severity, value, evidence, recommendation).
  - `findings`: temuan yang di-dedup per asset.
- Check **server** (via SSH, command tetap): CPU load, memori, disk, inode, service systemd yang gagal, port database yang terbuka ke semua interface, sinkronisasi NTP, pending reboot, konfigurasi SSH, serta proses mencurigakan (jalan dari `/tmp`/`/dev/shm`, atau nama crypto-miner).
- Check **website** (dari server manajemen):
  - status HTTP dan waktu respons;
  - redirect ke domain lain (indikasi malware);
  - redirect HTTP→HTTPS;
  - security headers dan kebocoran versi server;
  - sertifikat SSL (kedaluwarsa, hostname, versi TLS);
  - file sensitif yang terekspos (`.env`, `.git`, backup SQL, phpinfo, directory listing), dengan deteksi soft-404 untuk menghindari false positive;
  - **injeksi spam SEO/judi online** ("slot gacor", "togel", dll.), termasuk **cloaking**: konten spam yang hanya ditampilkan ke Googlebot.
- Check **malware di document root website** (via SSH ke server-nya):
  - heuristik webshell (`eval(base64_decode(...))`, `system($_POST...)`, dll.);
  - file PHP di folder uploads;
  - ClamAV dan YARA, **jika terpasang** di server target;
  - untuk YARA, rule bawaan aplikasi dikirim ke file sementara di server target lalu langsung dihapus.
- **Tidak ada file yang dihapus atau diubah otomatis** (sesuai PRD bagian 11).

**Keputusan default** (bisa diubah user)
| Topik | Default |
|---|---|
| Pemetaan status | Ada temuan CRITICAL/HIGH → RED; MEDIUM/LOW → YELLOW; tidak ada temuan → GREEN; check yang gagal dijalankan (ERROR) → minimal YELLOW |
| Ambang disk/inode | ≥80% YELLOW (MEDIUM), ≥90% RED (HIGH) |
| Ambang SSL | Kedaluwarsa / hostname tidak cocok → HIGH; <7 hari → HIGH; <30 hari → MEDIUM |
| ClamAV/YARA tidak terpasang | Check ditandai SKIPPED + rekomendasi pemasangan; aplikasi **tidak** meng-install apa pun di server target |
| Hak akses | Scan memakai user SSH apa adanya, **tanpa sudo**. File yang tidak bisa dibaca user tersebut tidak ter-scan |
| Format report | HTML (bisa di-print ke PDF dari browser), Markdown, JSON. PDF otomatis ditunda karena butuh Chromium di server |
| Dedup temuan | Temuan yang sama muncul lagi → diperbarui, bukan diduplikasi. Tidak muncul lagi → otomatis RESOLVED. Muncul kembali → REOPENED. Temuan yang ditandai FALSE_POSITIVE tidak memengaruhi status |

---

## 2026-09-24 — Build Fase 2: Assessment Engine (selesai & terverifikasi)

**File baru / berubah — backend `apps/api/`**
| Path | Isi |
|---|---|
| `app/models/assessment.py` | Tabel `assessments`, `assessment_checks`, `findings` |
| `app/assessment/types.py` | Format hasil check standar (PRD bagian 40) |
| `app/assessment/server_checks.py` | 10 check server via SSH (command tetap), dengan parser terpisah agar mudah dites |
| `app/assessment/web_checks.py` | Check website: HTTP, redirect, HTTPS, header, SSL/TLS, file terekspos, directory listing, spam judi & cloaking |
| `app/assessment/malware_scan.py` | Scan document root: heuristik webshell, PHP di uploads, ClamAV, YARA. Sinyal digabung per file |
| `app/assessment/rules/webshell.yar` | YARA rules bawaan (ditulis sendiri, konservatif) |
| `app/assessment/engine.py` | Orkestrasi, dedup temuan (new/persistent/resolved/reopened), status GREEN/YELLOW/RED |
| `app/reports/render.py` | Report HTML (auto-escape + CSP), Markdown, JSON |
| `app/api/v1/assessments.py` | Endpoint assessment, findings, triage, report |
| `app/api/v1/dashboard.py` | Metrik dashboard PRD bagian 6 |
| `alembic/versions/20260924_0002_assessments_and_findings.py` | Migrasi 0002 |
| `app/core/rbac.py` | Permission baru `finding:triage` (ADMIN, INFRA, SECURITY) |

**Endpoint API baru (prefix `/api/v1`)**
- `POST /assets/{id}/assess` (async via Celery; 409 jika masih ada yang berjalan)
- `POST /assessments/run-all`
- `GET /assessments`, `GET /assessments/{id}`
- `GET /assessments/{id}/report?format=html|markdown|json`
- `GET /findings`, `GET /findings/{id}`
- `POST /findings/{id}/acknowledge`, `POST /findings/{id}/false-positive` (catatan wajib diisi), `POST /findings/{id}/reopen`

**Frontend `apps/web/`**
- Halaman baru: `/findings` (filter status/severity/kategori + dialog triage), `/assessments` (riwayat + tombol "Assess semua asset"), `/assessments/[id]` (detail check + evidence + unduh report).
- Detail server/website: panel "Assessment terakhir", "Temuan aktif", dan "Timeline assessment" (PRD bagian 20).
- Dashboard: Red/Yellow/Green, temuan critical/high, diduga malware, service down, SSL, disk kritis, belum di-assess, dan daftar asset RED.

**Lab uji `infrastructure/lab/`**: container target yang sengaja disusupi (webshell palsu, `.env` terbuka, cloaking judi, proses "xmrig" palsu dari /tmp, dan signature ClamAV lokal). Khusus pengujian.

**Masalah yang ditemukan & diperbaiki selama build**
1. Output `df` di container memuat bind-mount (`/etc/hosts`) → mount semu disaring dan device yang sama di-dedup.
2. Judul check engine scan yang berstatus PASS tetapi menemukan file membingungkan → judul diperjelas ("… selesai — N file (lihat malware_file)").
3. Edit file lewat skrip Python di Windows memakai encoding cp1252 sehingga karakter "—" dan "…" rusak → diperbaiki, semua file sumber diverifikasi valid UTF-8, dan dicatat di memory agar tidak terulang.

**Hasil verifikasi**
- `pytest`: **88 passed**. Tes baru mencakup:
  - parser check server;
  - scan malware dengan runner palsu, termasuk 7 variasi percobaan injeksi `document_root` yang semuanya ditolak tanpa menjalankan command;
  - check website dengan situs palsu (soft-404 tanpa false positive, `.env`, `.git`, cloaking, redirect asing);
  - siklus hidup temuan, false positive, report yang meng-escape `<script>`, dan izin akses.
- Frontend: `tsc`, `eslint`, dan `next build` bersih.
- **Stack Docker sungguhan** (PostgreSQL + Redis + Celery worker + Caddy HTTPS):
  - migrasi 0001 dan 0002 berjalan;
  - `DELETE FROM audit_logs` ditolak database ("audit_logs is append-only").
- **Uji end-to-end terhadap lab** — semua masalah yang ditanam terdeteksi:
  - Server → RED: proses crypto-miner (CRITICAL), SSH root login (MEDIUM), SSH password auth (LOW).
  - Website → RED: `.env` terekspos (CRITICAL), cloaking judi ke Googlebot (CRITICAL), webshell (CRITICAL, confidence 100%, keempat sinyal: heuristik + uploads + ClamAV + YARA, lengkap dengan sha256/owner/mtime), directory listing, tanpa HTTPS, header, dan versi server.
  - File webshell **tetap ada** di server setelah scan (tidak dihapus otomatis), dan tidak ada file sementara YARA yang tertinggal.
  - Setelah webshell dihapus dan miner dihentikan, assessment ulang menandai kedua temuan **RESOLVED** otomatis; server turun ke YELLOW.
  - Audit `assessment.run` mencatat hash dari setiap command yang dijalankan.
- UI dicek visual di Microsoft Edge (headless), tanpa error JavaScript: dashboard, detail website, dialog temuan, detail assessment, dan report HTML.

**Status acceptance criteria PRD bagian 57**
- Assessment: [x] bisa dijalankan · [x] async · [x] hasil disimpan · [x] riwayat lama tetap ada · [x] status GREEN/YELLOW/RED
- Malware: [x] ClamAV · [x] YARA · [x] finding dibuat · [x] evidence disimpan · [x] file tidak dihapus otomatis
- Report: [x] dibuat · [x] ada severity · [x] temuan kritis disorot · [x] ada evidence · [x] ada rekomendasi · [x] ada timestamp

**Catatan / keterbatasan**
- Scan berjalan tanpa sudo: file yang tidak bisa dibaca user SSH tidak ter-scan.
- PDF belum otomatis; saat ini report HTML di-print ke PDF dari browser.
- Belum ada penjadwalan otomatis (scheduler ada di Fase 4); "Assess semua asset" masih manual.
- Deteksi spam memakai daftar kata kunci, jadi situs berita yang membahas judi bisa memicu temuan `content_injection` (confidence 60%). Bisa ditandai false positive.

**Langkah berikutnya yang disarankan**: uji ke 1–2 server/website sungguhan (staging), lalu Fase 3 (AI provider, chat per website, memory).

---

## 2026-09-25 — Perbaikan: akses via HTTP ke port HTTPS

**Laporan user**: membuka aplikasi menampilkan pesan `Client sent an HTTP request to an HTTPS server.`

**Analisis**
- Penyebab utama: alamat dibuka dengan `http://localhost:8443`. Port 8443 hanya melayani HTTPS, dan Caddy tidak bisa mengalihkan request HTTP yang masuk ke port TLS. Alamat yang benar adalah `https://localhost:8443`.
- Ditemukan bug terkait: port HTTP (8081) mengalihkan ke `https://localhost/` (port 443 default Caddy), bukan ke port HTTPS yang dipublikasikan (8443), sehingga redirect juga gagal.

**Perbaikan**
- `infrastructure/caddy/Caddyfile`: redirect otomatis Caddy dimatikan (`auto_https disable_redirects`), lalu ditambahkan blok `http://` yang mengalihkan ke `https://{host}:{HTTPS_PORT}`.
- `docker-compose.yml`: variabel `HTTPS_PORT` diteruskan ke container Caddy.

**Verifikasi**: `http://localhost:8081/login` → 301 → `https://localhost:8443/login` → 200.

**Cara akses**: `https://localhost:8443` (atau `http://localhost:8081`, yang kini otomatis dialihkan). Browser akan memperingatkan soal sertifikat karena Caddy memakai CA internal. Untuk lab ini, lanjutkan saja ("Advanced → Proceed").

---

## 2026-09-25 — Fase 3 (sebagian): AI Chat — rancangan & keputusan

**Permintaan user**: kolom chat AI di website, atau menu chat baru yang bisa memanggil semua server terdaftar.

**Rekomendasi yang disetujui user**
| Topik | Keputusan |
|---|---|
| Bentuk chat | **Keduanya**: menu global "AI Assistant" (semua server/website, bisa `@nama-asset`) + panel Chat di halaman detail tiap server/website. Satu engine yang sama |
| Provider untuk uji | **OpenAI / OpenAI-compatible** (user punya key). Adapter Anthropic (SDK resmi, default `claude-opus-5`) tetap dibuat |
| Hak AI | **Baca + usulan aksi**: AI membaca data lewat tool read-only; jika perlu menjalankan assessment, AI hanya menampilkan tombol konfirmasi dan user yang menekan |

**Rancangan**
- AI mengambil data lewat **tool read-only** (daftar asset, detail asset, temuan, hasil assessment, perbandingan assessment, ringkasan dashboard). Riwayat seluruh server tidak dikirim sekaligus (PRD bagian 46).
- Guardrail (PRD bagian 47–48):
  - tidak ada shell;
  - output tool diperlakukan sebagai data tak tepercaya;
  - deteksi pola prompt injection;
  - secret di-redact sebelum dikirim ke AI;
  - jawaban dipisah menjadi FAKTA / EVIDENCE / DUGAAN / REKOMENDASI.
- Halaman **Pengaturan AI** (ADMIN/SECURITY): provider, model, base URL, API key terenkripsi (AES-GCM, sama seperti credential SSH), tombol tes koneksi.
- Riwayat chat disimpan di database. Chat per asset bisa dilihat tim; chat global hanya milik pembuatnya.
- Semua chat dicatat di audit log (provider, model, token, tool yang dipakai).

---

## 2026-09-25 — Build AI Chat (selesai & terverifikasi)

**Backend `apps/api/`**
| Path | Isi |
|---|---|
| `app/models/ai.py` | Tabel `ai_providers`, `ai_conversations`, `ai_messages` (migrasi `0003`) |
| `app/ai/tools.py` | 8 tool read-only: `list_assets`, `get_asset`, `list_findings`, `get_finding`, `get_assessment`, `compare_assessments`, `dashboard_summary`, `propose_action` (hanya mengusulkan) |
| `app/ai/providers.py` | Adapter **OpenAI-compatible** (SDK `openai`) dan **Anthropic** (SDK resmi `anthropic`, default `claude-opus-5`) |
| `app/ai/engine.py` | System prompt, loop model ↔ tool (maks. 8 langkah), replay riwayat append-only, audit |
| `app/api/v1/ai.py` | Endpoint provider (ADMIN/SECURITY) dan percakapan |
| `app/core/redaction.py` | `redact_text()`: menyamarkan `KEY=value` rahasia, Bearer token, `sk-…`, AWS key, dan blok PEM di teks bebas |
| `infrastructure/lab/fake_openai.py` | LLM tiruan OpenAI-compatible untuk uji tanpa API key (khusus lab) |

**Endpoint baru (`/api/v1/ai`)**: `GET|POST /providers`, `PATCH|DELETE /providers/{id}`, `POST /providers/{id}/test`, `GET /providers/active`, `GET|POST /conversations`, `GET|DELETE /conversations/{id}`, `POST /conversations/{id}/messages`.

**Frontend `apps/web/`**
- Menu **AI Assistant** (`/assistant`): daftar percakapan, chat, autocomplete `@nama-asset`, dan contoh pertanyaan.
- Kartu **Chat AI** di halaman detail server & website. Riwayat per asset dibagikan ke tim.
- Menu **Pengaturan AI** (`/settings/ai`): tambah/ubah/hapus provider, API key (write-only), default, dan tes koneksi.
- Jawaban dirender sebagai Markdown tanpa HTML mentah. Tool yang dipakai AI ditampilkan sebagai label kecil (evidence). Usulan aksi muncul sebagai kartu dengan tombol **Jalankan (konfirmasi)**.

**Keamanan (PRD bagian 46–48)**
- AI tidak punya shell dan tidak bisa mengubah apa pun. `propose_action` hanya membuat tombol; assessment baru berjalan setelah user menekannya, dan izin role tetap dicek saat itu.
- Output tool di-redact sebelum dikirim ke provider. Secret dari `.env` yang terekspos juga disamarkan di evidence assessment baru.
- Teks yang mirip instruksi di dalam data (prompt injection) diberi peringatan sebelum sampai ke model; system prompt menyatakan bahwa data tool tidak tepercaya.
- API key disimpan dengan AES-GCM dan tidak pernah dikembalikan lewat API maupun ditulis ke audit.
- Chat global hanya terlihat oleh pembuatnya (ADMIN bisa melihat semua); chat per asset terlihat oleh tim.
- Untuk `claude-opus-5`, fallback refusal sisi server (`fallbacks: "default"`) aktif otomatis; blok `thinking`/`tool_use` dibersihkan sesuai aturan saat dikirim ulang.

**Hasil verifikasi**
- `pytest`: **98 passed**. 10 tes AI baru mencakup:
  - izin provider dan key write-only;
  - tool calling dan replay riwayat;
  - secret tidak sampai ke provider;
  - chat per asset, visibilitas, dan usulan yang tidak dieksekusi;
  - deteksi prompt injection;
  - error provider 401;
  - bentuk request Anthropic.
- Frontend: `tsc` dan `eslint` bersih; image web ter-build.
- **Stack Docker + LLM tiruan**: provider tersimpan dan tes koneksi berhasil. Pertanyaan "Asset mana saja yang statusnya RED?" → tool `list_assets` → "toko-batik-lab". Pertanyaan temuan kritis → `list_findings` menampilkan `.env` dan cloaking. Chat website "cek ulang" menghasilkan kartu usulan tanpa assessment berjalan otomatis. Audit mencatat `ai.chat`, `ai.provider.create`, dan `ai.provider.test` tanpa API key.
- UI dicek visual di Edge tanpa error.

**Catatan**
- Provider aktif di stack lokal saat ini adalah "Lab fake LLM" (tiruan). Untuk memakai OpenAI sungguhan, tambah provider baru di Pengaturan AI, centang "Jadikan default", lalu hapus atau nonaktifkan provider lab.
- Jawaban belum di-stream per token; AI menjawab setelah selesai mengambil data (biasanya beberapa detik).
- Data yang dikirim ke provider eksternal: pertanyaan user dan hasil tool (nama asset, temuan, hasil check) yang sudah di-redact. Jika kebijakan organisasi melarang data keluar, gunakan model lokal lewat endpoint OpenAI-compatible (vLLM/Ollama), sesuai PRD bagian 16.

---

## 2026-09-25 — Diagnosis: provider AI "AI-Assist" ditolak (401)

**Laporan user**: provider `AI-Assist` (OpenAI-compatible, model `qwen2`, base URL `https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1`) gagal dengan pesan "API key ditolak (401)". Menurut user, key itu berasal dari layanan LLM miliknya.

**Diagnosis** (dijalankan di container API; key tidak pernah dicetak)
- Format key bersih: 50 karakter, tidak ada spasi atau baris baru di awal/akhir.
- Key diawali `pxs`. Key Alibaba Cloud Model Studio biasanya diawali `sk-`.
- Respons asli provider:
  - `token-plan.ap-southeast-1.maas.aliyuncs.com` → `401 InvalidApiKey: Invalid API-key provided`
  - `dashscope-intl.aliyuncs.com` (Singapura) → `401 Incorrect API key provided`
  - `dashscope.aliyuncs.com` (China) → `401 Incorrect API key provided`
- Kesimpulan: Alibaba tidak mengenali key ini di endpoint mana pun. Kemungkinan besar key diterbitkan oleh layanan lain (misalnya gateway LLM internal atau produk lain) yang punya Base URL sendiri, atau key sudah dicabut/kedaluwarsa. Aplikasi sudah mengirim key dengan benar (`Authorization: Bearer …`).
- Catatan tambahan: nama model `qwen2` kemungkinan juga bukan nama model yang valid di Model Studio. Nama model harus persis seperti di dashboard provider.

**Perbaikan aplikasi**: pesan error 401/403/404 kini menampilkan pesan asli dari provider (sudah di-redact), ditambah petunjuk soal region/endpoint. Dengan begitu penyebabnya terlihat langsung dari tombol "Tes koneksi" tanpa diagnosis manual. File: `apps/api/app/ai/providers.py`; tes diperbarui (10/10 lolos); image API/worker di-deploy ulang.

**Menunggu dari user**: Base URL dan nama model dari dokumentasi/dashboard yang sama dengan tempat key dibuat.

---

## 2026-09-25 — Provider AI dihubungkan ke gateway LLM Proxsis (berhasil)

**Info dari user**: key `pxs…` berasal dari fitur "External Connection" pada LLM Proxsis (`POST /api/v1/chat/completions`, header `Authorization: Bearer <api_key>`). URL yang dikirim user: `https://llm-new.proxsis.com/v1`.

**Temuan**
- `https://llm-new.proxsis.com/v1/models` mengembalikan halaman web (HTML), bukan API. Base URL yang benar adalah **`https://llm-new.proxsis.com/api/v1`**.
- Model yang tersedia untuk key ini:
  - model knowledge base: `ollama_copy_9069` (Proxsis-KM Proxsa), `ollama_copy_4798` (KM Legal), `ollama_copy_7268` (KM Migas), `Policy`, `PROVAOffice`;
  - model umum: `Proxsis-DeepSeek4`, `Proxsis-GLM52`, `Proxsis-Kilo`, `Proxsis-Mimo25`.
- Uji tool calling (format OpenAI):
  - model **KM (knowledge base)** tidak memanggil tool; model menjawab dari dokumen internal. **Tidak cocok** untuk AI Assistant ini.
  - **Proxsis-DeepSeek4 (±2,7 dtk), GLM52, Kilo, Mimo25 mendukung tool calling dengan benar**.

**Perubahan konfigurasi** (lewat API, tercatat di audit)
- Provider `AI-Assist`: base URL `https://llm-new.proxsis.com/api/v1`, model `Proxsis-DeepSeek4`, dijadikan default.
- Provider `Lab fake LLM`: dinonaktifkan (tidak dihapus).

**Verifikasi end-to-end melalui aplikasi**
- Tes koneksi: berhasil ("OK, koneksi berjalan…").
- "Asset mana saja yang statusnya RED dan kenapa?" → tool `dashboard_summary`, `list_assets`, `list_findings`, `get_asset` → jawaban benar (toko-batik-lab, 6 temuan, tabel Fakta/Evidence/Dugaan/Rekomendasi); ±9,7 dtk, ±9 ribu token input.
- "Jelaskan temuan paling kritis di @toko-batik-lab…" → `get_finding` ×2 → jawaban akurat; `DB_PASSWORD` terlihat sebagai `***REDACTED***`, jadi secret tidak sampai ke LLM.

---

## 2026-09-25 — Tuning pemakaian token AI Chat

**Permintaan user**: pemakaian ±9–10 ribu token per pertanyaan dirasa terlalu besar.

**Pengukuran sebelum tuning**
| Sumber | Token (perkiraan) |
|---|---|
| System prompt kita | ~515 per panggilan model |
| Definisi 8 tool | ~965 per panggilan model |
| Prompt tambahan dari gateway Proxsis (di luar kontrol aplikasi) | ~600–850 per panggilan |
| Data hasil tool | hanya 50–260 per tool |

Kesimpulan: pemborosan utama adalah **jumlah bolak-balik ke model**. Pertanyaan "RED dan kenapa?" butuh 5 panggilan (4 tool berurutan + jawaban), dan tiap panggilan mengirim ulang overhead ±2.300 token. Selain itu, riwayat percakapan mengirim ulang seluruh data tool lama.

**Perubahan**
1. `get_asset` langsung menyertakan temuan aktif; `list_assets` punya opsi `include_findings`. Satu tool cukup untuk menjawab "kenapa RED".
2. `compare_assessments` digabung ke `get_assessment(compare=true)`; deskripsi tool diringkas. Overhead tool turun ~965 → ~724.
3. System prompt diringkas (~515 → ~379) dan menginstruksikan: kumpulkan data dalam sedikit langkah, panggil tool paralel, jawab ringkas (≤200 kata kecuali diminta detail).
4. Output tool berupa JSON padat tanpa field kosong/null.
5. Riwayat (khusus OpenAI-compatible): hanya giliran terakhir yang dikirim lengkap dengan data tool; giliran lebih lama dikirim sebagai teks tanya-jawab. Anthropic tetap memakai riwayat penuh (aturan append-only + prompt caching).
File: `apps/api/app/ai/tools.py`, `apps/api/app/ai/engine.py`, `apps/api/tests/test_ai_chat.py` (+2 tes).

**Hasil** (pertanyaan identik, model Proxsis-DeepSeek4)
| Pertanyaan | Input sebelum → sesudah | Output sebelum → sesudah |
|---|---|---|
| "Asset mana saja yang statusnya RED dan kenapa?" | 9.073 → 4.446 (−51%) | 788 → 378 (−52%) |
| "Jelaskan temuan paling kritis di @toko-batik-lab…" | 10.457 → 6.340 (−39%) | 997 → 593 (−41%) |
| Pertanyaan lanjutan tanpa tool | 3.591 | 231 |

Kualitas jawaban tetap (fakta sama, struktur Fakta/Dugaan/Rekomendasi dipertahankan) dan waktu respons turun dari ~10 menjadi ~6–7 detik. `pytest`: 100 passed.

**Batas yang tersisa**: gateway Proxsis menambahkan prompt sendiri (~600–850 token per panggilan) dan belum memakai prompt caching (`cached_tokens: 0`). Bagian ini hanya bisa dikurangi dari sisi admin Proxsis (misalnya opsi mematikan agent/system prompt bawaan untuk External Connection).

---

## 2026-09-26 — Rancangan: Jadwal pengecekan otomatis + Laporan Harian AI

**Permintaan user**: "tujuan utama saya agar AI-nya bisa diatur, misal 1 hari sekali melakukan pengecekan ke semua website."

**Klarifikasi arsitektur**: AI tidak mengakses server secara langsung (PRD bagian 60). Pengecekan dijalankan oleh assessment engine (SSH read-only + HTTP/SSL); AI membaca hasilnya lalu membuat analisis/ringkasan.

**Rancangan (PRD bagian 22, sebagian Fase 4)**
- Tabel `schedules`: nama, aktif/nonaktif, target (semua website / semua server / semua asset / asset pilihan), frekuensi (HARIAN jam:menit, MINGGUAN hari + jam, PER JAM menit ke-), zona waktu (default Asia/Jakarta), opsi "ringkasan AI", `next_run_at`.
- Tabel `schedule_runs`: satu eksekusi jadwal. Menyimpan assessment yang dibuat, hitungan status, dan **laporan AI**.
- Service baru `scheduler` (Celery Beat) di docker-compose: setiap 1 menit menjalankan `schedules.tick`, yang
  1. membuat run untuk jadwal yang jatuh tempo lalu mengantrekan assessment (trigger `SCHEDULED`);
  2. menutup run yang semua assessment-nya selesai, lalu meminta AI membuat laporan.
- Laporan AI dibuat dari **satu panggilan model** dengan ringkasan data yang sudah dipadatkan (tanpa tool loop), supaya hemat token.
- UI: menu **Jadwal** (buat/ubah/hapus, jalankan sekarang, riwayat run + laporan AI) dan kartu **Laporan AI terbaru** di Dashboard.
- Belum termasuk: notifikasi email/Telegram (perlu konfigurasi SMTP/bot) dan ekspresi cron bebas.

---

## 2026-09-26 — Build: Jadwal pengecekan otomatis + Laporan Harian AI (selesai & terverifikasi)

**Backend `apps/api/`**
| Path | Isi |
|---|---|
| `app/models/schedule.py` | Tabel `schedules` dan `schedule_runs`; kolom baru `assessments.schedule_run_id` (migrasi `0004`) |
| `app/services/scheduling.py` | `compute_next_run` (berbasis zona waktu), `fire` (antrekan assessment ke target), `tick` (jalankan jadwal jatuh tempo + tutup run yang selesai: hitung status, temuan baru/selesai, asset yang **memburuk**) |
| `app/services/assessments.py` | Logika antre assessment dipindah dari API agar dipakai bersama API dan scheduler |
| `app/ai/report.py` | Laporan Harian AI: data run dipadatkan (asset GREEN tanpa perubahan hanya dihitung, maks. 60 asset dirinci, di-redact), lalu **1 panggilan model tanpa tool** |
| `app/api/v1/schedules.py` | `GET/POST /schedules`, `PATCH/DELETE /schedules/{id}`, `POST /schedules/{id}/run-now`, `GET /schedule-runs`, `GET /schedule-runs/{id}` |
| `app/worker/tasks.py`, `celery_app.py` | Task `schedules.tick` (heartbeat 60 detik dari Celery Beat) dan `schedules.ai_report` |
| `docker-entrypoint.sh`, `docker-compose.yml` | Mode dan service baru **`scheduler`** (Celery Beat, cukup 1 instance) |

**Bug diperbaiki**: audit `assessment.request` sebelumnya mencatat `assessment_id: "None"` karena UUID baru terisi saat flush. Sekarang UUID dibuat eksplisit.

**Frontend `apps/web/`**
- Menu **Jadwal** (`/schedules`):
  - kartu jadwal (deskripsi mis. "Setiap hari pukul 02:00 WIB · Semua website · dengan laporan AI", waktu berikutnya/terakhir, ringkasan run terakhir);
  - tombol Jalankan sekarang, Aktifkan/Nonaktifkan, Ubah, Hapus;
  - form: target (semua website/server/semua/asset pilihan), frekuensi (harian/mingguan + hari/per jam), jam, zona WIB/WITA/WIT/UTC, laporan AI;
  - riwayat run dengan laporan AI (Markdown), status, dan asset yang memburuk.
- Dashboard: kartu **Laporan AI terbaru**.
- Label audit untuk `schedule.*` dan `ai.*`, serta filter "Jadwal" dan "AI" di halaman Audit Log.

**Hasil verifikasi**
- `pytest`: **106 passed**. 6 tes baru mencakup:
  - perhitungan jadwal WIB (harian, mingguan, per jam, batas tepat waktu);
  - validasi form dan izin akses;
  - `tick` menjalankan jadwal jatuh tempo, lalu laporan AI (secret evidence tidak ikut ke prompt, tanpa tools);
  - deteksi asset yang memburuk (GREEN→RED);
  - jadwal nonaktif tidak jalan;
  - tanpa provider AI → laporan ditandai FAILED dengan pesan jelas.
- Frontend: `tsc` dan `eslint` bersih; semua image ter-build.
- **Docker**: migrasi 0004 berjalan di PostgreSQL; service `scheduler` mengirim heartbeat tiap menit dan worker memprosesnya.
- **Uji sungguhan**: jadwal **"Pengecekan harian semua website" (setiap hari 02:00 WIB)** dibuat. Waktu jatuh tempo dimajukan sekali, lalu **scheduler otomatis** (trigger `SCHEDULED`) menjalankan assessment. Laporan AI dibuat oleh Proxsis-DeepSeek4 dengan **±1.666 token** (1.055 input + 611 output) dan isinya akurat. Jadwal berikutnya otomatis kembali ke 26 Sep 02:00 WIB.
- UI dicek visual di Edge tanpa error.

**Belum termasuk / catatan**
- Notifikasi email/Telegram saat ada RED atau laporan baru belum dibuat (perlu SMTP/bot).
- Ekspresi cron bebas belum didukung (harian/mingguan/per jam sudah mencakup kebutuhan PRD bagian 22).
- Service `scheduler` harus hanya 1 instance, supaya heartbeat tidak ganda (sudah dilindungi `SELECT … FOR UPDATE SKIP LOCKED`).

---

## 2026-09-26 — Fase 3 (sisa) + Fase 4: rancangan & keputusan

**Posisi roadmap**
- Fase 1–2 selesai.
- Fase 3 tinggal **Memory**.
- Fase 4: scheduler sudah ada; sisanya **approval workflow, remediation tools, backup + verifikasi**.
- Notifikasi email/Telegram ditunda sesuai arahan user ("lanjut fase selanjutnya dulu").

**Keputusan user**
| Topik | Keputusan |
|---|---|
| Remediation yang diizinkan | Karantina file, restart service, blokir akses file sensitif (semuanya lewat approval) |
| Siapa yang approve | ADMIN/SECURITY; **pengaju boleh menyetujui sendiri** (tanpa aturan 4-mata) |
| Lokasi backup | Disk server aplikasi ini (volume Docker), ditarik lewat SSH |
| Hak akses server target | User SSH sudah punya akses (tanpa sudo) |

**Rancangan**
1. **Memory (PRD bagian 17)**
   - Catatan per asset atau global, jenis ASSET/OPERATIONAL/SECURITY (mis. "pernah kena malware Maret 2026", "disk sering penuh karena log", "file X adalah agent backup resmi").
   - Memory ikut dibaca AI saat chat dan laporan.
   - AI boleh **mengusulkan** catatan baru; user yang menyimpan.
2. **Approval + Remediation (PRD bagian 23–25, 49)**
   - Tabel `actions` dengan status PENDING_APPROVAL → APPROVED → RUNNING → SUCCEEDED/FAILED, atau REJECTED/CANCELLED.
   - Preview command (dry-run) terlihat sebelum approve.
   - Command dibangun dari template tetap dengan validasi parameter.
   - **Karantina**: simpan hash/stat/owner/permission → pindahkan file ke `~/.aiinfra-quarantine/<id>/` → `chmod 000`. Tidak pernah menghapus; bisa dikembalikan lewat rollback.
   - **Batasi akses file**: `chmod 600` + catat permission asli untuk rollback.
   - **Restart service**: `systemctl restart <nama>` + cek `is-active`.
   - Setelah berhasil, assessment ulang otomatis untuk verifikasi.
   - Aksi bisa diajukan dari dialog temuan atau dari usulan AI.
3. **Backup (PRD bagian 13)**
   - Jadwal jenis BACKUP memakai menu Jadwal yang sama.
   - Proses: `tar.gz` document root via SSH (dialirkan ke disk lokal), hitung sha256, lalu **verifikasi** (arsip dibaca utuh + jumlah file dicocokkan dengan server) dan retensi N backup terakhir.
   - Status backup GREEN/YELLOW/RED menjadi check di assessment website.
   - Unduh backup: khusus ADMIN, karena arsip bisa berisi secret seperti `.env`/`wp-config`.
   - Backup database dan restore ke produksi ditunda (perlu credential DB; restore = tindakan CRITICAL).

---

## 2026-09-26 — Build Fase 3 (Memory) + Fase 4 (Approval, Remediation, Backup) — selesai & terverifikasi

### Tahap 1 — Memory (PRD bagian 17)
- Tabel `memories` (per asset atau global; jenis ASSET / OPERATIONAL / SECURITY; sumber USER atau AI).
- API `GET/POST /memories`, `PATCH/DELETE /memories/{id}`. Izin `memory:manage` untuk ADMIN, INFRA, SECURITY; role lain hanya bisa membaca.
- AI: memory dimasukkan ke konteks setiap percakapan dan ke output `get_asset`. AI bisa **mengusulkan** catatan (`propose_action: save_memory`); user yang menekan "Simpan ke memory".
- UI: kartu **Memory** di detail server/website, dan **Memory global** di Pengaturan AI.

### Tahap 2 — Approval + Remediation (PRD bagian 23–25, 49)
- Tabel `actions` dengan status PENDING_APPROVAL → APPROVED → RUNNING → SUCCEEDED/FAILED, atau REJECTED/CANCELLED.
- Izin: `action:request` (ADMIN, INFRA, SECURITY) dan `action:approve` (ADMIN, SECURITY). **Boleh menyetujui permintaan sendiri** sesuai keputusan user; audit mencatat `self_approved`.
- Jenis tindakan: Karantina file (HIGH), Batasi akses file `chmod 600` (HIGH), Restart service (LOW), serta rollback-nya (kembalikan dari karantina / kembalikan permission).
- Pengaman:
  - path divalidasi ketat (untuk website harus di dalam document root; untuk server hanya /var/www, /srv, /home, /opt, /tmp, dll.; `/etc`, `.ssh`, dan folder karantina ditolak);
  - nama service divalidasi;
  - command dibangun dari template tetap dan di-quote dengan `shlex`;
  - **preview command** tampil sebelum approve;
  - host key server wajib sudah di-pin (tidak ada TOFU untuk tindakan tulis);
  - eksekusi berhenti di langkah pertama yang gagal lalu diverifikasi;
  - **assessment ulang otomatis** setelah berhasil (trigger `POST_ACTION`);
  - tidak ada penghapusan file.
- Karantina: bukti (stat + sha256) → `~/.aiinfra-quarantine/<id>/file` (chmod 000) + `meta.txt`.
- AI bisa mengusulkan remediation; usulan itu menjadi permintaan yang tetap harus di-approve.
- Data `get_asset` untuk AI kini menyertakan **riwayat tindakan terbaru**, supaya AI tidak salah menyimpulkan (sebelumnya AI menduga "reinfeksi" padahal file kembali karena rollback yang disengaja; setelah perbaikan AI menjelaskannya dengan benar).
- UI:
  - menu **Tindakan** (filter status, preview command, approve/tolak dengan catatan, batalkan, hasil tiap langkah, ajukan rollback) dengan badge jumlah pending di sidebar;
  - tombol **"Ajukan tindakan"** di dialog temuan, terisi otomatis (malware_file / suspicious_process → karantina; exposed_file → batasi akses dengan path dari document root; failed_services → restart).

### Tahap 3 — Backup + verifikasi (PRD bagian 13)
- Tabel `backups`; jadwal kini punya **jenis pekerjaan** (ASSESSMENT / BACKUP). Kolom `job` ditambahkan dengan default `ASSESSMENT`, sehingga jadwal harian user yang sudah ada tetap utuh.
- Proses:
  - `tar -czf -` document root dialirkan langsung lewat SSH ke volume `backups` (tanpa file sementara di server target);
  - sha256 dihitung saat transfer;
  - **verifikasi**: arsip dibaca utuh (CRC gzip) + jumlah file dicocokkan dengan `find` di server (toleransi 1%);
  - retensi 7 backup per website; batas ukuran 20 GB dan batas waktu 3 jam.
- Status backup menjadi check `backup_status` di assessment website: belum ada backup → LOW (HIGH untuk website kritikal); gagal → MEDIUM/HIGH; tidak terverifikasi → HIGH; lebih dari 48 jam → MEDIUM.
- API: `GET /backups/overview`, `GET/POST /backups`, `GET /backups/{id}`, `GET /backups/{id}/download` (**khusus ADMIN**, tercatat di audit, path dibatasi ke folder backup).
- UI: menu **Backup** (status per website, backup sekarang, riwayat dengan sha256 & unduh) dan pilihan jenis Backup di form Jadwal.
- Docker: volume `backups` untuk api + worker; folder `/backups` dimiliki appuser.

### Migrasi
- `0005`: `memories`, `actions`, `backups`, kolom `job` di `schedules`/`schedule_runs` (dengan `server_default` agar aman untuk data yang sudah ada). Upgrade/downgrade/check lolos; di PostgreSQL berjalan tanpa kehilangan jadwal user.

### Hasil verifikasi
- `pytest`: **133 passed**. Tes baru: memory (2), tindakan (16, termasuk 9 variasi path berbahaya yang ditolak), backup (9, termasuk **streaming lewat server SSH sungguhan** dan deteksi arsip rusak).
- Frontend: `tsc`, `eslint`, dan `next build` bersih.
  - Bug ditemukan: `export function` di file `page.tsx` akan menggagalkan build Next.js; sudah diperbaiki.
- **Uji end-to-end di Docker terhadap server lab (SSH sungguhan)**:
  - backup berhasil dan terverifikasi (4/4 file), `backup_status` PASS;
  - karantina: file tetap ada sebelum approve; setelah approve file pindah ke folder karantina (mode 000, sha256 + stat tercatat); assessment ulang otomatis menandai temuan malware **RESOLVED**;
  - rollback karantina: file kembali (644, owner ops);
  - `.env` 755 → 600 → rollback 755;
  - restart service di lab tanpa systemd: FAILED dengan pesan jelas (`systemctl: command not found`);
  - `/etc/passwd` ditolak (422);
  - memory dibaca AI (Proxsis-DeepSeek4).
- **Temuan saat uji**: unduhan backup pertama gagal di host Windows (`bad record mac`), padahal dari dalam Docker berhasil (HTTP/1.1 & HTTP/2).
  - Penyebab: **Avast Antivirus (Web Shield)** di komputer ini memeriksa HTTPS dan memblokir arsip yang berisi sampel webshell lab.
  - Terbukti: backup kedua **tanpa** webshell berhasil diunduh dari host dengan sha256 cocok.
  - Ini perilaku antivirus yang benar, bukan bug aplikasi.
- **Perbaikan lab**: `start.sh` di lab tidak lagi menimpa signature ClamAV dengan nilai kosong saat container di-restart setelah sampel dikarantina.
- UI dicek visual di Edge (Tindakan, Backup, dialog Ajukan tindakan) tanpa error.

### Belum termasuk
- Notifikasi email/Telegram (ditunda sesuai arahan user).
- Backup database (butuh credential DB per website) dan **restore ke produksi** (tindakan CRITICAL, perlu desain approval khusus).
- Arsip backup belum dienkripsi at-rest. Simpan volume `backups` di disk terenkripsi dan batasi akses host.

---

## 2026-09-26 — Rancangan: Notifikasi (penutup Fase 4) + Fase 5 (Wazuh)

**Permintaan user**: siapkan konfigurasi SMTP (data SMTP menyusul) dan, bila bisa, webhook. Untuk Fase 5, kantor sudah memakai Wazuh.

**Keputusan user (Wazuh)**
| Topik | Keputusan |
|---|---|
| Versi | **Wazuh 4.14.5** (≥ 4.8: data kerentanan ada di Wazuh Indexer) |
| Akses | **Server API (port 55000) + Indexer (port 9200)**, read-only |
| Pengujian | Langsung ke Wazuh kantor, **nanti**. Sekarang dibangun dan diuji dengan tiruan (mock) yang formatnya mengikuti dokumentasi resmi |

**Referensi yang dicek di dokumentasi resmi Wazuh**
- Autentikasi: `POST /security/user/authenticate?raw=true` (basic auth) → token Bearer; port 55000.
- Format daftar API: `data.affected_items`, `total_affected_items`.
- Index Indexer: `wazuh-alerts-*` (alert), `wazuh-states-vulnerabilities-*` (kerentanan: `vulnerability.id`, `vulnerability.severity`, `vulnerability.score.base`, `agent.*`, `package.*`), `wazuh-states-inventory-*`.

**Rancangan A — Notifikasi**
- Kanal: **Email (SMTP)** (host, port, STARTTLS/SSL/tanpa enkripsi, user, password terenkripsi, pengirim, penerima), **Webhook** (format JSON generik dengan tanda tangan HMAC-SHA256, atau format Slack-compatible), **Telegram** (bot token terenkripsi + chat id).
- Event yang bisa dipilih per kanal: asset menjadi RED, temuan HIGH/CRITICAL baru, dugaan malware, SSL bermasalah, asset tidak terjangkau, backup gagal/tidak terverifikasi, assessment gagal, tindakan menunggu approval, Laporan AI harian.
- Hanya dikirim saat **ada perubahan** (temuan baru/muncul kembali, status berubah menjadi RED), jadi tidak berulang setiap assessment.
- Semua event juga masuk **notifikasi in-app** (lonceng). Pengiriman tercatat dengan retry otomatis; ada tombol **tes kirim** per kanal.

**Rancangan B — Fase 5: Wazuh**
- Pengaturan integrasi: URL + user/password Server API dan Indexer (password terenkripsi), verifikasi TLS (opsional CA sendiri), level alert minimum.
- Sinkron agent (berkala): daftar agent Wazuh dan pemetaan otomatis ke server (berdasarkan nama/IP), bisa diubah manual.
- Assessment server menambahkan check dari Wazuh (tanpa SSH):
  - status agent;
  - alert level tinggi 24 jam terakhir;
  - perubahan file (FIM) di folder web;
  - kerentanan (CVE) per severity;
  - skor SCA (hardening).
- AI mendapat tool **threat hunting** read-only: cari alert per asset, cari **IOC** (IP / hash / nama file) di seluruh agent, dan lihat kerentanan.
- Tahap lanjut Fase 5: **alur insiden** dan **baseline hash file** (PRD bagian 50).

---

## 2026-09-25 — Build: Notifikasi (SMTP/Webhook/Telegram) + Fase 5 Integrasi Wazuh

**Backend**
- Model + migrasi `0006`: `notification_channels`, `notification_events`, `notification_deliveries`, `users.notifications_seen_at`, `wazuh_config` (1 baris), `wazuh_agents`.
- Permission baru: `notify:manage` dan `integration:manage` (dimiliki SECURITY; ADMIN memiliki semua).
- `services/notify.py`:
  - `emit()` mencatat event lalu mengantrekan pengiriman per kanal yang berlangganan.
  - Transport: SMTP (STARTTLS/SSL/tanpa enkripsi), webhook (JSON + header `X-AIInfra-Signature: sha256=<HMAC>`, atau format Slack `{text}`), Telegram (token tidak pernah muncul di pesan error).
  - Retry 3× (1 menit, lalu 5 menit).
- Pemicu event:
  - setelah assessment: RED baru, temuan HIGH/CRITICAL baru, malware, SSL, tidak terjangkau, assessment gagal;
  - backup gagal/tidak terverifikasi;
  - tindakan menunggu approval;
  - Laporan AI jadwal;
  - alert Wazuh.
- Event dikirim hanya saat ada perubahan, jadi tidak berulang di setiap assessment.
- API `/notifications`:
  - kanal CRUD + tes kirim (rahasia write-only);
  - riwayat pengiriman;
  - feed in-app, jumlah belum dibaca, tandai sudah dibaca.
- `services/wazuh.py` (read-only):
  - Server API: login JWT dengan login ulang otomatis saat token kedaluwarsa, daftar agent (paginasi), SCA.
  - Indexer: alert, FIM, kerentanan, pencarian IOC. Query berupa JSON DSL, tanpa penggabungan string.
- Sinkron agent tiap 15 menit, dipetakan otomatis ke server berdasarkan nama/IP (bisa diubah manual).
- Check Wazuh di setiap assessment server:
  - `wazuh_agent`;
  - `wazuh_alerts` (level ≥13 CRITICAL, ≥10 HIGH, ≥7 MEDIUM, di atas level minimum);
  - `wazuh_fim` (file skrip di folder web);
  - `wazuh_vulnerabilities`;
  - `wazuh_sca`.
- Jika Wazuh down, hasilnya menjadi check ERROR dan assessment tetap berjalan.
- Poller alert tiap 5 menit mengirim event `wazuh_alert` (near real-time) tanpa duplikasi.
- Tool AI baru (hanya muncul jika Wazuh aktif): `wazuh_alerts`, `wazuh_vulnerabilities`, `search_ioc`.
- API `/integrations/wazuh`:
  - pengaturan (password write-only, CA PEM);
  - tes koneksi;
  - sinkron;
  - daftar dan pemetaan agent.

**Frontend**
- Sidebar dikelompokkan menjadi Operasional / Keamanan / Pengaturan.
- Badge: jumlah notifikasi belum dibaca (merah) dan tindakan pending (kuning).
- Halaman **Notifikasi**: feed dengan penanda "baru", otomatis ditandai sudah dibaca saat dibuka, tautan ke asset.
- **Pengaturan → Kanal notifikasi**:
  - form Email/Webhook/Telegram (port otomatis mengikuti mode keamanan);
  - checklist event, aktif/nonaktif, "Kirim uji" beserta hasilnya;
  - riwayat pengiriman.
- **Pengaturan → Integrasi Wazuh**:
  - form Server API + Indexer, CA PEM, level alert minimum;
  - "Simpan & tes koneksi" (menampilkan versi API/Indexer);
  - tabel agent dengan dropdown pemetaan ke server (atau Otomatis).
- Label audit baru: `notify.*`, `integration.wazuh.*`, `ai.conversation.delete`.

**Lab uji baru** (khusus pengujian):
- `infrastructure/lab/fake_wazuh.py`: Wazuh 4.14.5 tiruan (API :55000 + Indexer :9200) dengan agent `lab-target`.
- `infrastructure/lab/webhook_sink.py`: penerima webhook yang memverifikasi HMAC.
- Mailpit sebagai SMTP tiruan.
- Cara menjalankan ada di README.

**Bug yang ditemukan dan diperbaiki saat uji di Docker/PostgreSQL**
1. **Notifikasi gagal tersimpan di PostgreSQL** (foreign key violation). Baris pengiriman bisa ter-INSERT sebelum baris event karena keduanya tidak dihubungkan `relationship()`.
   - Perbaikan: `emit()` melakukan `flush()` event lebih dulu.
   - Tes tidak menangkapnya karena SQLite tidak menegakkan FK secara default. Sekarang `PRAGMA foreign_keys=ON` di `tests/conftest.py`. Terbukti: tanpa perbaikan tes gagal, dengan perbaikan lulus.
2. **CA Wazuh terhapus** saat pengaturan disimpan tanpa mengirim `ca_cert`.
   - Perbaikan: field yang tidak dikirim berarti CA dipertahankan; `null` berarti dihapus. Ditambah tes.
3. Tautan "Buka: …" di email/webhook kosong karena `APP_BASE_URL` belum diteruskan ke container.
   - Perbaikan: ditambahkan ke `docker-compose.yml` dan `.env.example`.

**Verifikasi**
- `pytest`: **147 lulus** (FK ditegakkan).
- `tsc`, `eslint`, `next build` bersih.
- Migrasi `0006` sudah head di PostgreSQL.
- E2E di stack Docker:
  - Tes kanal: Email → Mailpit (2 penerima), Webhook JSON (tanda tangan HMAC valid), Slack (`{text}`) → semua "Terkirim".
  - Wazuh tiruan: tes koneksi API 4.14.5 + Indexer 2.19.1; sinkron 2 agent, `lab-target` terpetakan otomatis ke server lab-target, `db-kantor-01` tidak cocok.
  - Assessment server lab-target: 7 check Wazuh muncul:
    - agent aktif;
    - alert "web attack returned code 200" dan "sshd brute force" (HIGH);
    - FIM `shell.php` di uploads;
    - CVE Critical/High;
    - SCA 48%.
  - Poller: 1 event `wazuh_alert` level 12.
  - Pengiriman: 5 SENT, 0 FAILED. Email dan webhook berisi event `new_findings` + `wazuh_alert`.
  - Badge Notifikasi = 2.
  - Screenshot semua halaman baru: tanpa error browser.

**Catatan desain**: alert Wazuh diumumkan oleh poller (`wazuh_alert`), sehingga tidak diulang sebagai "temuan baru" oleh assessment (menghindari notifikasi ganda).

**Menunggu dari user**
- Detail SMTP kantor → tambah kanal Email di UI lalu "Kirim uji".
- Wazuh kantor → URL API/Indexer, user read-only, `root-ca.pem`, lalu "Simpan & tes koneksi" dan "Sinkron agent". Pastikan container dapat menjangkau port 55000/9200.
- Sisa Fase 5: alur insiden dan baseline hash file (PRD 50).

---
