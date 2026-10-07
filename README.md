# AI Infrastructure & Website Security Assistant

Aplikasi internal on-premise untuk mengelola dan meng-assess server serta website.
Spesifikasi lengkap ada di [`AI-Infrastructure-Website-Security-Assistant-PRD.md`](AI-Infrastructure-Website-Security-Assistant-PRD.md),
dan log pengerjaan ada di [`aktivitas.md`](aktivitas.md).

**Status: Fase 1–4 selesai · Fase 5: integrasi Wazuh selesai (uji ke Wazuh kantor menyusul)**
- Fase 1: auth, RBAC, dashboard, inventory server/website, credential terenkripsi, tes koneksi SSH, audit log.
- Fase 2: assessment server & website (health, HTTP, SSL, header, file terekspos, spam judi/cloaking),
  scan malware document root (heuristik webshell, ClamAV, YARA), findings dengan dedup/resolve otomatis,
  status GREEN/YELLOW/RED, report HTML/Markdown/JSON.
- AI Chat: menu "AI Assistant" (semua asset, @mention) + chat per server/website; provider OpenAI-compatible
  atau Anthropic diatur di menu "Pengaturan AI"; AI hanya membaca data dan mengusulkan aksi (butuh konfirmasi).
- Jadwal: pengecekan otomatis (harian/mingguan/per jam, zona WIB/WITA/WIT) ke semua website/server atau asset
  pilihan, diikuti Laporan AI (1 panggilan model per run). Service `scheduler` (Celery Beat) di docker-compose.
- Memory: catatan per asset/global yang selalu dibaca AI (AI boleh mengusulkan, user yang menyimpan).
- Tindakan (remediation) dengan approval ADMIN/SECURITY: karantina file, batasi akses file (chmod 600), restart
  service. Preview command sebelum approve, verifikasi sesudahnya, assessment ulang otomatis, dan rollback.
- Backup document root website ke volume `backups` + verifikasi (arsip dibaca utuh, jumlah file dicocokkan),
  retensi 7 backup, dijadwalkan lewat menu Jadwal (jenis Backup). Unduh khusus ADMIN.
- Notifikasi: menu Notifikasi (feed + badge belum dibaca) dan kanal di Pengaturan → Kanal notifikasi:
  Email (SMTP STARTTLS/SSL/tanpa enkripsi), Webhook (JSON bertanda tangan HMAC `X-AIInfra-Signature`, atau format
  Slack-compatible), Telegram. Hanya dikirim saat ada perubahan; gagal kirim dicoba ulang 3×.
- Wazuh 4.x (read-only, Server API + Indexer): sinkron & pemetaan agent → server, cek alert/FIM/CVE/SCA di setiap
  assessment server, notifikasi alert level tinggi tiap 5 menit, dan tool AI (alert, CVE, cari IOC).

## Struktur

```text
apps/api/      FastAPI + SQLAlchemy + Alembic + Celery (Python 3.12)
apps/web/      Next.js 15 + TypeScript + Tailwind + shadcn/ui + TanStack Query
infrastructure/caddy/Caddyfile   reverse proxy (HTTPS internal)
docker-compose.yml               postgres(pgvector) · redis · api · worker · scheduler · web · reverse-proxy
```

## Menjalankan dengan Docker Compose (disarankan)

```bash
cp .env.example .env
# isi semua nilai di .env (lihat komentar di file itu untuk cara generate secret)
docker compose up -d --build
```

Buka `https://<SITE_ADDRESS>`, lalu login dengan `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD`.
Akun admin pertama ini hanya dibuat jika tabel user masih kosong. Setelah login pertama, segera ganti
password di menu **Akun**, lalu hapus kedua variabel tersebut dari `.env`.

> **Penting:** `SECRET_MASTER_KEY` mengenkripsi semua credential. Simpan backup-nya terpisah dari
> backup database. Jika key ini hilang, semua SSH key dan API key yang tersimpan tidak bisa dipulihkan.

Membuat user tambahan lewat CLI (password diminta lewat prompt):

```bash
docker compose exec api python -m app.cli create-user --email ops@corp.local --name "Ops" --role INFRA
```

## Lab uji (opsional)

`infrastructure/lab/` berisi server target yang **sengaja disusupi** untuk menguji deteksi
(webshell palsu, `.env` terbuka, cloaking judi untuk Googlebot, proses "miner" palsu dari `/tmp`).
Hanya untuk pengujian — jangan pernah dipakai di lingkungan nyata.

```bash
docker build -t aiinfra-lab-target infrastructure/lab
docker run -d --name lab-target --hostname lab-target --network ai-sitkorp_default aiinfra-lab-target
# di aplikasi: credential SSH_PASSWORD user "ops" / "LabOnly-Passw0rd!", server hostname "lab-target",
# website http://lab-target:8080/ dengan document root /var/www/site

# LLM tiruan (OpenAI-compatible) untuk menguji AI chat tanpa API key:
docker run -d --name fake-llm --network ai-sitkorp_default \
  -v "$PWD/infrastructure/lab/fake_openai.py:/app/fake_openai.py:ro" python:3.12-slim python /app/fake_openai.py
# di Pengaturan AI: jenis OpenAI-compatible, base URL http://fake-llm:9000/v1, model bebas

# SMTP tiruan (Mailpit, UI di http://localhost:8025) + penerima webhook (http://localhost:9009/received):
docker run -d --name mailpit --network ai-sitkorp_default -p 8025:8025 axllent/mailpit
docker run -d --name webhook-sink --network ai-sitkorp_default -p 9009:9000 \
  -v "$PWD/infrastructure/lab/webhook_sink.py:/app/webhook_sink.py:ro" python:3.12-slim python /app/webhook_sink.py
# kanal Email: host mailpit, port 1025, keamanan "Tanpa enkripsi"; kanal Webhook: http://webhook-sink:9000/siem,
# signing secret lab-webhook-secret (sink memverifikasi tanda tangan)

# Wazuh tiruan (Server API :55000 + Indexer :9200, agent "lab-target"):
docker run -d --name fake-wazuh --network ai-sitkorp_default \
  -v "$PWD/infrastructure/lab/fake_wazuh.py:/app/fake_wazuh.py:ro" python:3.12-slim python /app/fake_wazuh.py
# Integrasi Wazuh: API http://fake-wazuh:55000 wazuh-wui / lab-api-pass,
# Indexer http://fake-wazuh:9200 admin / lab-idx-pass
```

## Menghubungkan ke Wazuh & SMTP sungguhan

- **Wazuh**: buat user API dengan role `readonly` dan user Indexer dengan akses baca ke `wazuh-alerts-*` dan
  `wazuh-states-vulnerabilities-*`. Isi di Pengaturan → Integrasi Wazuh, tempel `root-ca.pem` Wazuh agar
  verifikasi TLS tetap aktif, lalu "Simpan & tes koneksi" → "Sinkron agent". Pastikan container `api`/`worker`
  bisa menjangkau port 55000 dan 9200.
- **SMTP**: tambah kanal Email (host, port 587 STARTTLS / 465 SSL, user, password, pengirim, penerima) lalu
  "Kirim uji". Set `APP_BASE_URL` di `.env` agar email/webhook memuat tautan "Buka: …" ke aplikasi.

## Development lokal (tanpa Docker)

Backend:

```bash
cd apps/api
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt     # Linux/macOS: .venv/bin/pip
# siapkan env: DATABASE_URL, JWT_SECRET, SECRET_MASTER_KEY, REDIS_URL
# tanpa Redis: CELERY_TASK_ALWAYS_EAGER=true (task dijalankan langsung di proses API)
.venv/Scripts/alembic upgrade head
.venv/Scripts/uvicorn app.main:app --reload --port 8000
.venv/Scripts/python -m pytest          # 147 tes, memakai SQLite in-memory (FK ditegakkan)
```

Frontend:

```bash
cd apps/web
npm install
npm run dev        # http://localhost:3000, request /api diteruskan ke 127.0.0.1:8000
```

Dokumentasi API interaktif tersedia di `/api/docs` (dinonaktifkan jika `ENVIRONMENT=production`).

## Prinsip keamanan yang diterapkan

- Secret (SSH key, password, API key) dienkripsi dengan AES-256-GCM dan **tidak pernah** dikembalikan oleh API.
- AI/automation tidak punya shell bebas. Semua aksi ke server lewat tool terdaftar dengan command tetap (`app/tools/registry.py`).
- Host key SSH di-pin saat koneksi pertama. Jika host key berubah, koneksi diblokir sampai admin mereset-nya.
- Setiap aksi tercatat di audit log (append-only; di PostgreSQL UPDATE/DELETE ditolak oleh trigger).
- Akun dikunci 15 menit setelah 5 kali gagal login. Logout dan ganti password membatalkan semua sesi.
- Assessment bersifat read-only: tidak ada file yang dihapus/diubah otomatis; temuan malware berstatus SUSPECTED.
- ClamAV/YARA dipakai jika terpasang di server target — aplikasi tidak meng-install apa pun di sana.
- Konten dari server/website yang diperiksa diperlakukan sebagai data tak tepercaya (di-escape di UI & report,
  report HTML dilayani dengan CSP tanpa script).
